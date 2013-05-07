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

from quantum.common import exceptions
from quantum.openstack.common import log as logging
from quantum.openstack.common import timeutils

from quark.db import api as db_api


LOG = logging.getLogger("quantum")


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
            # TODO(mdietz): IP allocation hack, remove +3 later
            if ipnet.size > (ips_in_subnet + 3):
                return subnet

        raise exceptions.IpAddressGenerationFailure(net_id=net_id)

    def allocate_mac_address(self, context, net_id, port_id, reuse_after,
                             mac_address=None):
        if mac_address:
            mac_address = netaddr.EUI(mac_address).value

        deallocated_mac = db_api.mac_address_find(
            context, reuse_after=reuse_after, scope=db_api.ONE,
            address=mac_address)
        if deallocated_mac:
            return db_api.mac_address_update(
                context, deallocated_mac, deallocated=False,
                deallocated_at=None)

        ranges = db_api.mac_address_range_find_allocation_counts(
            context, address=mac_address)
        for result in ranges:
            rng, addr_count = result
            if rng["last_address"] - rng["first_address"] <= addr_count:
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

            address = db_api.mac_address_create(context, address=next_address,
                                                mac_address_range_id=rng["id"])
            return address

        raise exceptions.MacAddressGenerationFailure(net_id=net_id)

    def allocate_ip_address(self, context, net_id, port_id, reuse_after,
                            version=None, ip_address=None):
        elevated = context.elevated()
        if ip_address:
            ip_address = netaddr.IPAddress(ip_address)

        address = db_api.ip_address_find(
            elevated, network_id=net_id, reuse_after=reuse_after,
            deallocated=True, scope=db_api.ONE, ip_address=ip_address)
        if address:
            return db_api.ip_address_update(
                elevated, address, deallocated=False, deallocated_at=None)

        subnet = self._choose_available_subnet(
            elevated, net_id, ip_address=ip_address, version=version)

        # Creating this IP for the first time
        next_ip = None
        if ip_address:
            next_ip = ip_address
        else:
            address = True
            while address:
                next_ip_int = int(subnet["next_auto_assign_ip"])
                next_ip = netaddr.IPAddress(next_ip_int)
                if subnet["ip_version"] == 4:
                    next_ip = next_ip.ipv4()
                subnet["next_auto_assign_ip"] = next_ip_int + 1
                address = db_api.ip_address_find(
                    elevated,
                    network_id=net_id,
                    ip_address=next_ip,
                    tenant_id=elevated.tenant_id,
                    scope=db_api.ONE)

        # TODO(mdietz): this is a hack until we have IP policies
        ip_int = int(next_ip)
        diff = ip_int - subnet["first_ip"]
        if diff < 2:
            next_ip = netaddr.IPAddress(ip_int + (2 - diff))
        if ip_int == subnet["last_ip"]:
            raise exceptions.IpAddressGenerationFailure(net_id=net_id)
        if next_ip not in netaddr.IPNetwork(subnet["cidr"]):
            raise exceptions.IpAddressGenerationFailure(net_id=net_id)

        address = db_api.ip_address_create(
            elevated, address=next_ip, subnet_id=subnet["id"],
            version=subnet["ip_version"], network_id=net_id)

        return address

    def deallocate_ip_address(self, context, port, **kwargs):
        for address in port["ip_addresses"]:
            # Only disassociate from port, don't automatically deallocate
            address["ports"].remove(port)
            if len(address["ports"]) > 0:
                continue

            address["deallocated"] = 1

    def deallocate_mac_address(self, context, address):
        mac = db_api.mac_address_find(context, address=address,
                                      scope=db_api.ONE)
        if not mac:
            raise exceptions.NotFound(
                message="No MAC address %s found" % netaddr.EUI(address))
        db_api.mac_address_update(context, mac, deallocated=True,
                                  deallocated_at=timeutils.utcnow())
