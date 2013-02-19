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

import netaddr

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.ext import hybrid

from quantum.db.model_base import BASEV2
from quantum.db.models_v2 import HasTenant, HasId
from quantum.openstack.common import timeutils
from quantum.openstack.common import log as logging

LOG = logging.getLogger("quantum")


class CreatedAt(object):
    created_at = sa.Column(sa.DateTime(), default=timeutils.utcnow)


# TODO(mdietz): discuss any IP reservation policies ala Melange with the nerds
# but not sure if we need them offhand
#
# Things omitted:
#
# shared or sharing fields from any of the tables. If we're going to implement
# actual sharing, then we need to provide AuthZ as well as reasonable
# constructs for said sharing. Then the act of sharing will be implicit in
# those structures.
#
# Most of the IPAM model from upstream. It seemed unwieldy, and ended up
# providing what Subnet with a CIDR defined
#
# status fields. In most cases, they seemed superfluous. We prefer to delete
# ports when they're not in use. Meanwhile, I don't see a need for a network
# that exists but might have a state that means it's unusable.
#
# IP octets and policies from Melange, for now
#
# DNS and DHCP things. Don't need them right now, not sure we'd ever
# have to implement those unless Quark completely co-opts upstream
#
# Most of the fields on routes. I think the simpler cidr and gateway
# denotation is more meaningful and easier.


class IPAddress(BASEV2, CreatedAt, HasId, HasTenant):
    """More closely emulate the melange version of the IP table.
    We always mark the record as deallocated rather than deleting it.
    Gives us an IP address owner audit log for free, essentially"""

    __tablename__ = "quark_ip_addresses"

    address_readable = sa.Column(sa.String(128), nullable=False)

    address = sa.Column(sa.LargeBinary(16), nullable=False)

    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey("quark_subnets.id",
                                        ondelete="CASCADE"))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("quark_networks.id",
                                         ondelete="CASCADE"))
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey("quark_ports.id", ondelete="CASCADE"))

    version = sa.Column(sa.Integer())

    # Need a constant to facilitate the indexed search for new IPs
    _deallocated = sa.Column(sa.Boolean())

    @hybrid.hybrid_property
    def deallocated(self):
        return self._deallocated

    @deallocated.setter
    def deallocated(self, val):
        self._deallocated = val
        self.deallocated_at = timeutils.utcnow()

    @deallocated.expression
    def deallocated(cls):
        return IPAddress._deallocated

    def formatted(self):
        ip = netaddr.IPAddress(self.address_readable)
        if self.version == 4:
            return str(ip.ipv4())
        return str(ip.ipv6())

    deallocated_at = sa.Column(sa.DateTime())


class Route(BASEV2, CreatedAt, HasTenant, HasId):
    __tablename__ = "quark_routes"
    cidr = sa.Column(sa.String(64))
    gateway = sa.Column(sa.String(64))
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey("quark_subnets.id"))


class Subnet(BASEV2, CreatedAt, HasId, HasTenant):
    """
    Upstream model for IPs

    Subnet -> has_many(IPAllocationPool)
    IPAllocationPool -> has_many(IPAvailabilityRange)
        As well as first and last _ip markers for some unknown reason
        first_ip is min(ranges), last_ip is max(ranges)
    IPAvailabilityRange -> belongs_to(IPAllocationPool)
        Also has first and last _ip, but only for the range
    IPAllocation -> belongs_to(port, subnet, network) but NOT IPAllocationPool

    IPAllocationPool and Range seem superfluous. Just create intelligent CIDRs
    for your subnet
    """
    __tablename__ = "quark_subnets"
    network_id = sa.Column(sa.String(36), sa.ForeignKey('quark_networks.id'))
    _cidr = sa.Column(sa.String(64), nullable=False)

    @hybrid.hybrid_property
    def cidr(self):
        return self._cidr

    @cidr.setter
    def cidr(self, val):
        self._cidr = val
        preip = netaddr.IPNetwork(val)
        self.version = preip.version
        ip = netaddr.IPNetwork(val).ipv6()
        self.first_ip = ip.first
        self.last_ip = ip.last

    @cidr.expression
    def cidr(cls):
        return Subnet._cidr
    
    first_ip = sa.Column(sa.LargeBinary())
    last_ip = sa.Column(sa.LargeBinary())
    version = sa.Column(sa.Integer())

    allocated_ips = orm.relationship(IPAddress, backref="subnet")
    routes = orm.relationship(Route, backref='subnet', cascade='delete')


class Port(BASEV2, CreatedAt, HasId, HasTenant):
    __tablename__ = "quark_ports"
    network_id = sa.Column(sa.String(36), sa.ForeignKey("quark_networks.id"),
                           nullable=False)

    nvp_id = sa.Column(sa.String(36), nullable=False)
    # Maybe have this for optimizing lookups.
    # subnet_id = sa.Column(sa.String(36), sa.ForeignKey("subnets.id"),
    #                      nulllable=False)
    mac_address = sa.Column(sa.BigInteger(),
                            sa.ForeignKey("quark_mac_addresses.address"))

    # device is an ID pertaining to the entity utilizing the port. Could be
    # an instance, a load balancer, or any other network capable object
    device_id = sa.Column(sa.String(255), nullable=False)


class MacAddress(BASEV2, CreatedAt, HasTenant):
    __tablename__ = "quark_mac_addresses"
    address = sa.Column(sa.BigInteger(), primary_key=True)
    mac_address_range_id = sa.Column(sa.String(36),
                                sa.ForeignKey("quark_mac_address_ranges.id"),
                                nullable=False)
    deallocated = sa.Column(sa.Boolean())
    deallocated_at = sa.Column(sa.DateTime())
    orm.relationship(Port, backref="mac_address")


class MacAddressRange(BASEV2, CreatedAt, HasId):
    __tablename__ = "quark_mac_address_ranges"
    cidr = sa.Column(sa.String(255), nullable=False)
    first_address = sa.Column(sa.BigInteger(), nullable=False)
    last_address = sa.Column(sa.BigInteger(), nullable=False)


class Network(BASEV2, CreatedAt, HasTenant, HasId):
    __tablename__ = "quark_networks"
    name = sa.Column(sa.String(255))
    ports = orm.relationship(Port, backref='network')
    subnets = orm.relationship(Subnet, backref='network')
