# Copyright 2013 Openstack LLC.
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

import datetime

import netaddr

from sqlalchemy import func as sql_func
from quantum.common import exceptions
from quantum.openstack.common import log as logging
from quark.db import models


LOG = logging.getLogger("quantum")


class QuarkIpam(object):

    def _choose_available_subnet(self, net_id, session):
        subnets = session.query(models.Subnet,
                                sql_func.count(models.IPAddress.subnet_id).
                                    label('count')).\
                    with_lockmode("update").\
                    outerjoin(models.Subnet.allocated_ips).\
                    group_by(models.IPAddress).\
                    order_by("count DESC").\
                    all()

        if not subnets:
            raise exceptions.IpAddressGenerationFailure(net_id=net_id)
        for subnet in subnets:
            ip = netaddr.IPNetwork(subnet[0]["cidr"])
            if ip.size > subnet[1]:
                return subnet[0]

        raise exceptions.IpAddressGenerationFailure(net_id=net_id)

    def allocate_mac_address(self, session, net_id, port_id, tenant_id,
                             reuse_after):
        reuse = (datetime.datetime.utcnow() -
                        datetime.timedelta(seconds=reuse_after))
        deallocated_mac = session.query(models.MacAddress).\
                            filter(models.MacAddress.deallocated == 1).\
                            filter(models.MacAddress.deallocated_at <= reuse).\
                            first()
        if deallocated_mac:
            deallocated_mac["deallocated"] = False
            deallocated_mac["deallocated_at"] = None
            return deallocated_mac

        ranges = session.query(models.MacAddressRange,
                               sql_func.count(models.MacAddress).
                               label("count")).\
                        outerjoin(models.MacAddress).\
                        group_by(models.MacAddressRange).\
                        order_by("count DESC").\
                        all()
        if not ranges:
            raise exceptions.MacAddressGenerationFailure(net_id=net_id)
        for result in ranges:
            rng, addr_count = result
            if rng["last_address"] - rng["first_address"] <= addr_count:
                continue
            highest_mac = session.query(models.MacAddress).\
                            filter(models.MacAddress.mac_address_range_id ==
                                   rng["id"]).\
                            order_by("address DESC").\
                            first()
            address = models.MacAddress()
            if highest_mac:
                next_mac = netaddr.EUI(highest_mac["address"]).value
                address["address"] = next_mac + 1
            else:
                address["address"] = rng["first_address"]

            address["mac_address_range_id"] = rng["id"]
            address["tenant_id"] = tenant_id
            session.add(address)
            return address

        raise exceptions.MacAddressGenerationFailure(net_id=net_id)

    def allocate_ip_address(self, session, net_id, port_id, reuse_after):
        reuse = (datetime.datetime.utcnow() -
                        datetime.timedelta(seconds=reuse_after))
        address = session.query(models.IPAddress).\
                          filter(models.IPAddress.network_id == net_id).\
                          filter(models.IPAddress.port_id == None).\
                          filter(models.IPAddress._deallocated == 1).\
                          filter(models.IPAddress.deallocated_at <= reuse).\
                          first()
        if not address:
            subnet = self._choose_available_subnet(net_id, session)
            highest_addr = session.query(models.IPAddress).\
                                filter(models.IPAddress.subnet_id ==
                                                        subnet["id"]).\
                                order_by("address DESC").\
                                first()

            # TODO(mdietz): Need to honor policies here
            address = models.IPAddress()
            if highest_addr:
                next_ip = netaddr.IPAddress(int(highest_addr["address"])) + 1
                address["address"] = int(next_ip)
                address["address_readable"] = str(next_ip)
            else:
                first_address = netaddr.IPAddress(int(subnet["first_ip"]))
                address["address"] = int(first_address)
                address["address_readable"] = str(first_address)

            address["subnet_id"] = subnet["id"]
            address["version"] = subnet["ip_version"]
            address["network_id"] = net_id
            address["tenant_id"] = subnet["tenant_id"]

        if address:
            address["port_id"] = port_id
            session.add(address)
            address["ip_address"] = address.formatted()
            return address
        raise exceptions.IpAddressGenerationFailure(net_id=net_id)

    def deallocate_ip_address(self, session, port_id, **kwargs):
        address = session.query(models.IPAddress).\
                          filter(models.IPAddress.port_id == port_id).\
                          first()
        if not address:
            LOG.critical("No IP assigned or already deallocated")
            return
        address["deallocated"] = 1

    def deallocate_mac_address(self, session, address):
        mac = session.query(models.MacAddress).\
                        filter(models.MacAddress.address == address).\
                        first()
        if not mac:
            mac_pretty = netaddr.EUI(address)
            raise exceptions.NotFound(
                        message="No MAC address %s found" % mac_pretty)
        mac["deallocated"] = True
        mac["deallocated_at"] = datetime.datetime.utcnow()
        session.add(mac)
