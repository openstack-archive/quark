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

    def allocate_ip_address(self, session, net_id, port_id):
        address = session.query(models.IPAddress).\
                          filter(models.IPAddress.network_id == net_id).\
                          filter(models.IPAddress.deallocated != 1).\
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

        if address:
            address["port_id"] = port_id
            address["subnet_id"] = subnet["id"]
            address["network_id"] = net_id
            address["tenant_id"] = subnet["tenant_id"]
            session.add(address)
            return address
        raise exceptions.IpAddressGenerationFailure(net_id=net_id)

    def deallocate_ip_address(self, session, port_id, **kwargs):
        LOG.critical("Deallocating port %s." % port_id)
        address = session.query(models.IPAddress).\
                          filter(models.IPAddress.port_id == port_id).\
                          first()
        if not address:
            LOG.critical("No IP assigned or already deallocated")
            return
        reuse_after_deallocate = kwargs.get("ipam_reuse_ip_instantly", False)
        if reuse_after_deallocate:
            address["deallocated"] = 0
        else:
            address["deallocated"] = 1
