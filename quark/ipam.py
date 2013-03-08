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

import datetime

import netaddr

from sqlalchemy import func as sql_func
from quantum.common import exceptions
from quantum.openstack.common import log as logging
from quantum.openstack.common import timeutils
from quark.db import models


LOG = logging.getLogger("quantum")


class QuarkIpam(object):

    def _choose_available_subnet(self, net_id, session):
        subnets = session.query(models.Subnet,
                                sql_func.count(models.IPAddress.subnet_id).
                                label('count')).\
            outerjoin(models.Subnet.allocated_ips).\
            filter(models.Subnet.network_id == net_id).\
            group_by(models.IPAddress).\
            order_by("count DESC").\
            all()

        for subnet, ips_in_subnet in subnets:
            ipnet = netaddr.IPNetwork(subnet["cidr"])
            if ipnet.size > ips_in_subnet:
                return subnet

        raise exceptions.IpAddressGenerationFailure(net_id=net_id)

    def allocate_mac_address(self, session, net_id, port_id, tenant_id,
                             reuse_after):
        reuse = (timeutils.utcnow() -
                 datetime.timedelta(seconds=reuse_after))
        query = session.query(models.MacAddress)
        query = query.filter_by(deallocated=True)
        query = query.filter(models.MacAddress.deallocated_at <= reuse)

        deallocated_mac = query.first()

        if deallocated_mac:
            deallocated_mac["deallocated"] = False
            deallocated_mac["deallocated_at"] = None
            return deallocated_mac

        ranges = session.query(models.MacAddressRange,
                               sql_func.count(models.MacAddress.address).
                               label("count")).\
            outerjoin(models.MacAddress).\
            group_by(models.MacAddressRange).\
            order_by("count DESC").\
            all()

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
            address["deallocated"] = False
            address["deallocated_at"] = None
            return address

        raise exceptions.MacAddressGenerationFailure(net_id=net_id)

    def allocate_ip_address(self, session, net_id, port_id, reuse_after):
        reuse = (timeutils.utcnow() -
                 datetime.timedelta(seconds=reuse_after))
        query = session.query(models.IPAddress)
        query = query.filter_by(network_id=net_id)
        query = query.filter_by(deallocated=False)
        query = query.filter(models.IPAddress.deallocated_at <= reuse)

        address = query.first()

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
            address["_deallocated"] = 0

        if address:
            address["port_id"] = port_id
            return address
        raise exceptions.IpAddressGenerationFailure(net_id=net_id)

    def deallocate_ip_address(self, session, port_id, **kwargs):
        # NOTE(jkoelker) Get on primary key will not cause SQL lookup
        #                if the object is already in the session
        port = session.query(models.Port).get(port_id)
        if not port:
            raise exceptions.NotFound(
                message="No port found with id=%s" % port_id)
        for address in port['ip_addresses']:
            # NOTE(jkoelker) Address is used by multiple ports only
            #                remove it from this port
            if len(address['ports']) > 1:
                address['ports'].remove(port)
                continue

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
        mac["deallocated_at"] = timeutils.utcnow()
