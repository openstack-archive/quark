# Copyright 2013 Openstack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Quark Pluggable IPAM
"""

import netaddr

from neutron.common import exceptions
from neutron.openstack.common import log as logging
from neutron.openstack.common.notifier import api as notifier_api
from neutron.openstack.common import timeutils

from oslo.config import cfg

from quark.db import api as db_api
from quark.db import models


LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class QuarkIpam(object):
    def allocate_mac_address(self, context, net_id, port_id, reuse_after,
                             mac_address=None):
        if mac_address:
            mac_address = netaddr.EUI(mac_address).value

        with context.session.begin(subtransactions=True):
            deallocated_mac = db_api.mac_address_find(
                context, lock_mode=True, reuse_after=reuse_after,
                scope=db_api.ONE, address=mac_address)
            if deallocated_mac:
                return db_api.mac_address_update(
                    context, deallocated_mac, deallocated=False,
                    deallocated_at=None)

        with context.session.begin(subtransactions=True):
            ranges = db_api.mac_address_range_find_allocation_counts(
                context, address=mac_address)
            for result in ranges:
                rng, addr_count = result
                last = rng["last_address"]
                first = rng["first_address"]
                if last - first <= addr_count:
                    continue
                next_address = None
                if mac_address:
                    next_address = mac_address
                else:
                    address = True
                    while address:
                        next_address = rng["next_auto_assign_mac"]
                        rng["next_auto_assign_mac"] = next_address + 1
                        address = db_api.mac_address_find(
                            context, tenant_id=context.tenant_id,
                            scope=db_api.ONE, address=next_address)

                address = db_api.mac_address_create(
                    context, address=next_address,
                    mac_address_range_id=rng["id"])
                return address

        raise exceptions.MacAddressGenerationFailure(net_id=net_id)

    def attempt_to_reallocate_ip(self, context, net_id, port_id, reuse_after,
                                 version=None, ip_address=None):
        version = version or [4, 6]
        elevated = context.elevated()

        # We never want to take the chance of an infinite loop here. Instead,
        # we'll clean up multiple bad IPs if we find them (assuming something
        # is really wrong)
        for times in xrange(3):
            with context.session.begin(subtransactions=True):
                address = db_api.ip_address_find(
                    elevated, network_id=net_id, reuse_after=reuse_after,
                    deallocated=True, scope=db_api.ONE, ip_address=ip_address,
                    lock_mode=True, version=version, order_by="address")

                if address:
                    #NOTE(mdietz): We should always be in the CIDR but we've
                    #              also said that before :-/
                    if address.get("subnet"):
                        cidr = netaddr.IPNetwork(address["subnet"]["cidr"])
                        addr = netaddr.IPAddress(address["address"],
                                                 version=cidr.version)
                        if addr in cidr:
                            updated_address = db_api.ip_address_update(
                                elevated, address, deallocated=False,
                                deallocated_at=None,
                                allocated_at=timeutils.utcnow())
                            return [updated_address]
                        else:
                            # Make sure we never find it again
                            context.session.delete(address)
                            continue
                break
        return []

    def is_strategy_satisfied(self, ip_addresses):
        return ip_addresses

    def _iterate_until_available_ip(self, context, subnet, network_id,
                                    ip_policy_rules):
        address = True
        while address:
            next_ip_int = int(subnet["next_auto_assign_ip"])
            next_ip = netaddr.IPAddress(next_ip_int)
            if subnet["ip_version"] == 4:
                next_ip = next_ip.ipv4()
            subnet["next_auto_assign_ip"] = next_ip_int + 1
            if ip_policy_rules and next_ip in ip_policy_rules:
                continue
            address = db_api.ip_address_find(
                context, network_id=network_id, ip_address=next_ip,
                tenant_id=context.tenant_id, scope=db_api.ONE)

        ipnet = netaddr.IPNetwork(subnet["cidr"])
        next_addr = netaddr.IPAddress(
            subnet["next_auto_assign_ip"])
        if ipnet.is_ipv4_mapped() or ipnet.version == 4:
            next_addr = next_addr.ipv4()
        return next_ip

    def allocate_ip_address(self, context, net_id, port_id, reuse_after,
                            version=None, ip_address=None):
        elevated = context.elevated()
        if ip_address:
            ip_address = netaddr.IPAddress(ip_address)

        new_addresses = []
        realloc_ips = self.attempt_to_reallocate_ip(context, net_id,
                                                    port_id, reuse_after,
                                                    version=None,
                                                    ip_address=None)
        if self.is_strategy_satisfied(realloc_ips):
            return realloc_ips
        new_addresses.extend(realloc_ips)
        with context.session.begin(subtransactions=True):
            subnets = self._choose_available_subnet(
                elevated, net_id, version, ip_address=ip_address,
                reallocated_ips=realloc_ips)
            for subnet in subnets:
                ip_policy_rules = models.IPPolicy.get_ip_policy_rule_set(
                    subnet)
                # Creating this IP for the first time
                next_ip = None
                if ip_address:
                    next_ip = ip_address
                    address = db_api.ip_address_find(
                        elevated, network_id=net_id, ip_address=next_ip,
                        tenant_id=elevated.tenant_id, scope=db_api.ONE)
                    if address:
                        raise exceptions.IpAddressGenerationFailure(
                            net_id=net_id)
                else:
                    next_ip = self._iterate_until_available_ip(
                        elevated, subnet, net_id, ip_policy_rules)

                context.session.add(subnet)
                address = db_api.ip_address_create(
                    elevated, address=next_ip, subnet_id=subnet["id"],
                    version=subnet["ip_version"], network_id=net_id)
                address["deallocated"] = 0
                new_addresses.append(address)

        for addr in new_addresses:
            payload = dict(tenant_id=addr["tenant_id"],
                           ip_block_id=addr["subnet_id"],
                           ip_address=addr["address_readable"],
                           device_ids=[p["device_id"] for p in addr["ports"]],
                           created_at=addr["created_at"])
            notifier_api.notify(context,
                                notifier_api.publisher_id("network"),
                                "ip_block.address.create",
                                notifier_api.CONF.default_notification_level,
                                payload)
        return new_addresses

    def _deallocate_ip_address(self, context, address):
        address["deallocated"] = 1
        payload = dict(tenant_id=address["tenant_id"],
                       ip_block_id=address["subnet_id"],
                       ip_address=address["address_readable"],
                       device_ids=[p["device_id"] for p in address["ports"]],
                       created_at=address["created_at"],
                       deleted_at=timeutils.utcnow())
        notifier_api.notify(context,
                            notifier_api.publisher_id("network"),
                            "ip_block.address.delete",
                            notifier_api.CONF.default_notification_level,
                            payload)

    def deallocate_ip_address(self, context, port, **kwargs):
        with context.session.begin(subtransactions=True):
            for addr in port["ip_addresses"]:
                # Note: only deallocate ip if this is the only port mapped
                if len(addr["ports"]) == 1:
                    self._deallocate_ip_address(context, addr)
            port["ip_addresses"] = []

    def deallocate_mac_address(self, context, address):
        with context.session.begin(subtransactions=True):
            mac = db_api.mac_address_find(context, address=address,
                                          scope=db_api.ONE)
            if not mac:
                raise exceptions.NotFound(
                    message="No MAC address %s found" % netaddr.EUI(address))
            db_api.mac_address_update(context, mac, deallocated=True,
                                      deallocated_at=timeutils.utcnow())

    def select_subnet(self, context, net_id, ip_address, **filters):
        subnets = db_api.subnet_find_allocation_counts(context, net_id,
                                                       scope=db_api.ALL,
                                                       **filters)
        for subnet, ips_in_subnet in subnets:
            ipnet = netaddr.IPNetwork(subnet["cidr"])
            if ip_address and ip_address not in ipnet:
                continue
            ip_policy_rules = None
            if not ip_address:
                ip_policy_rules = models.IPPolicy.get_ip_policy_rule_set(
                    subnet)
            policy_size = ip_policy_rules.size if ip_policy_rules else 0
            if ipnet.size > (ips_in_subnet + policy_size):
                return subnet


class QuarkIpamANY(QuarkIpam):
    @classmethod
    def get_name(self):
        return "ANY"

    def _choose_available_subnet(self, context, net_id, version=None,
                                 ip_address=None, reallocated_ips=None):
        filters = {}
        if version:
            filters["ip_version"] = version
        subnet = self.select_subnet(context, net_id, ip_address, **filters)
        if subnet:
            return [subnet]
        raise exceptions.IpAddressGenerationFailure(net_id=net_id)


class QuarkIpamBOTH(QuarkIpam):
    @classmethod
    def get_name(self):
        return "BOTH"

    def is_strategy_satisfied(self, reallocated_ips):
        req = [4, 6]
        for ip in reallocated_ips:
            if ip is not None:
                req.remove(ip["version"])
        if len(req) == 0:
            return True
        return False

    def attempt_to_reallocate_ip(self, context, net_id, port_id,
                                 reuse_after, version=None,
                                 ip_address=None):
        both_versions = []
        with context.session.begin(subtransactions=True):
            for ver in (4, 6):
                address = super(QuarkIpamBOTH, self).attempt_to_reallocate_ip(
                    context, net_id, port_id, reuse_after, ver, ip_address)
                both_versions.extend(address)
        return both_versions

    def _choose_available_subnet(self, context, net_id, version=None,
                                 ip_address=None, reallocated_ips=None):
        both_subnet_versions = []
        need_versions = [4, 6]
        for i in reallocated_ips:
            if i["version"] in need_versions:
                need_versions.remove(i["version"])
        filters = {}
        for ver in need_versions:
            filters["ip_version"] = ver
            sub = self.select_subnet(context, net_id, ip_address, **filters)

            if sub:
                both_subnet_versions.append(sub)
        if not reallocated_ips and not both_subnet_versions:
            raise exceptions.IpAddressGenerationFailure(net_id=net_id)

        return both_subnet_versions


class QuarkIpamBOTHREQ(QuarkIpamBOTH):
    @classmethod
    def get_name(self):
        return "BOTH_REQUIRED"

    def _choose_available_subnet(self, context, net_id, version=None,
                                 ip_address=None, reallocated_ips=None):
        subnets = super(QuarkIpamBOTHREQ, self)._choose_available_subnet(
            context, net_id, version, ip_address, reallocated_ips)

        if len(reallocated_ips) + len(subnets) < 2:
            raise exceptions.IpAddressGenerationFailure(net_id=net_id)
        return subnets


class IpamRegistry(object):
    def __init__(self):
        self.strategies = {
            QuarkIpamANY.get_name(): QuarkIpamANY(),
            QuarkIpamBOTH.get_name(): QuarkIpamBOTH(),
            QuarkIpamBOTHREQ.get_name(): QuarkIpamBOTHREQ()}

    def is_valid_strategy(self, strategy_name):
        if strategy_name in self.strategies:
            return True
        return False

    def get_strategy(self, strategy_name):
        if self.is_valid_strategy(strategy_name):
            return self.strategies[strategy_name]
        fallback = CONF.QUARK.default_ipam_strategy
        LOG.warn("IPAM strategy %s not found, "
                 "using default %s" % (strategy_name, fallback))
        return self.strategies[fallback]


IPAM_REGISTRY = IpamRegistry()
