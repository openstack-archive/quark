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
    def _choose_available_subnet(self, context, net_id, version=None,
                                 ip_address=None):
        filters = {}
        if version:
            filters["version"] = version
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

        raise exceptions.IpAddressGenerationFailure(net_id=net_id)

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

    def allocate_ip_address(self, context, net_id, port_id, reuse_after,
                            version=None, ip_address=None):
        elevated = context.elevated()
        if ip_address:
            ip_address = netaddr.IPAddress(ip_address)

        with context.session.begin(subtransactions=True):
            address = db_api.ip_address_find(
                elevated, network_id=net_id, reuse_after=reuse_after,
                deallocated=True, scope=db_api.ONE, ip_address=ip_address,
                lock_mode=True)

            if address:
                updated_address = db_api.ip_address_update(
                    elevated, address, deallocated=False,
                    deallocated_at=None)
                return updated_address

        with context.session.begin(subtransactions=True):
            subnet = self._choose_available_subnet(
                elevated, net_id, ip_address=ip_address, version=version)
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
                        elevated, network_id=net_id, ip_address=next_ip,
                        tenant_id=elevated.tenant_id, scope=db_api.ONE)
            context.session.add(subnet)
            address = db_api.ip_address_create(
                elevated, address=next_ip, subnet_id=subnet["id"],
                version=subnet["ip_version"], network_id=net_id)
            address["deallocated"] = 0

        payload = dict(tenant_id=address["tenant_id"],
                       ip_block_id=address["subnet_id"],
                       ip_address=address["address_readable"],
                       device_ids=[p["device_id"] for p in address["ports"]],
                       created_at=address["created_at"])

        notifier_api.notify(context,
                            notifier_api.publisher_id("network"),
                            "ip_block.address.create",
                            notifier_api.CONF.default_notification_level,
                            payload)

        return address

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
