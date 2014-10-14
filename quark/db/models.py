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

import netaddr
import neutron.db.model_base
from neutron.db import models_v2 as models
from neutron.openstack.common import log as logging
from neutron.openstack.common import timeutils
import sqlalchemy as sa
from sqlalchemy.ext import associationproxy
from sqlalchemy.ext import declarative
from sqlalchemy.ext import hybrid
from sqlalchemy import orm

from quark.db import custom_types
# NOTE(mdietz): This is the only way to actually create the quotas table,
#              regardless if we need it. This is how it's done upstream.
# NOTE(jhammond): If it isn't obvious quota_driver is unused and that's ok.
#                 DO NOT DELETE IT!!!
from quark import quota_driver  # noqa

HasId = models.HasId

LOG = logging.getLogger(__name__)
TABLE_KWARGS = {"mysql_engine": "InnoDB"}


def _default_list_getset(collection_class, proxy):
    attr = proxy.value_attr

    def getter(obj):
        if obj:
            return getattr(obj, attr, None)
        return []

    if collection_class is dict:
        setter = lambda o, k, v: setattr(o, attr, v)
    else:
        setter = lambda o, v: setattr(o, attr, v)
    return getter, setter


class QuarkBase(neutron.db.model_base.NeutronBaseV2):
    created_at = sa.Column(sa.DateTime(), default=timeutils.utcnow)
    __table_args__ = TABLE_KWARGS


BASEV2 = declarative.declarative_base(cls=QuarkBase)


class TagAssociation(BASEV2, models.HasId):
    __tablename__ = "quark_tag_associations"

    discriminator = sa.Column(sa.String(255))
    tags = associationproxy.association_proxy("tags_association", "tag",
                                              creator=lambda t: Tag(tag=t))

    @classmethod
    def creator(cls, discriminator):
        return lambda tags: TagAssociation(tags=tags,
                                           discriminator=discriminator)

    @property
    def parent(self):
        """Return the parent object."""
        return getattr(self, "%s_parent" % self.discriminator)


class Tag(BASEV2, models.HasId, models.HasTenant):
    __tablename__ = "quark_tags"
    association_uuid = sa.Column(sa.String(36),
                                 sa.ForeignKey(TagAssociation.id),
                                 nullable=False)

    tag = sa.Column(sa.String(255), nullable=False)
    parent = associationproxy.association_proxy("association", "parent")
    association = orm.relationship("TagAssociation",
                                   backref=orm.backref("tags_association"))


class IsHazTags(object):
    @declarative.declared_attr
    def tag_association_uuid(cls):
        return sa.Column(sa.String(36), sa.ForeignKey(TagAssociation.id),
                         nullable=True)

    @declarative.declared_attr
    def tag_association(cls):
        discriminator = cls.__name__.lower()
        creator = TagAssociation.creator(discriminator)
        kwargs = {'creator': creator,
                  'getset_factory': _default_list_getset}
        cls.tags = associationproxy.association_proxy("tag_association",
                                                      "tags", **kwargs)
        backref = orm.backref("%s_parent" % discriminator, uselist=False)
        return orm.relationship("TagAssociation", backref=backref)


port_ip_association_table = sa.Table(
    "quark_port_ip_address_associations",
    BASEV2.metadata,
    # We just need sqlalchemy to think these are primary keys
    sa.Column("port_id", sa.String(36),
              sa.ForeignKey("quark_ports.id"), nullable=False,
              primary_key=True),
    sa.Column("ip_address_id", sa.String(36),
              sa.ForeignKey("quark_ip_addresses.id"), nullable=False,
              primary_key=True),
    sa.Column("enabled", sa.Boolean(), default=True, nullable=False,
              server_default='1'),
    **TABLE_KWARGS)


class IPAddress(BASEV2, models.HasId):
    """More closely emulate the melange version of the IP table.

    We always mark the record as deallocated rather than deleting it.
    Gives us an IP address owner audit log for free, essentially.
    """
    __tablename__ = "quark_ip_addresses"
    __table_args__ = (sa.UniqueConstraint("subnet_id", "address",
                                          name="subnet_id_address"),
                      TABLE_KWARGS)

    address_readable = sa.Column(sa.String(128), nullable=False)
    address = sa.Column(custom_types.INET(), nullable=False, index=True)
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey("quark_subnets.id",
                                        ondelete="CASCADE"))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("quark_networks.id",
                                         ondelete="CASCADE"))
    version = sa.Column(sa.Integer(), index=True)
    allocated_at = sa.Column(sa.DateTime())
    subnet = orm.relationship("Subnet")
    # Need a constant to facilitate the indexed search for new IPs
    _deallocated = sa.Column(sa.Boolean())
    # Legacy data
    used_by_tenant_id = sa.Column(sa.String(255))

    @hybrid.hybrid_property
    def deallocated(self):
        return self._deallocated and not self.ports

    @deallocated.setter
    def deallocated(self, val):
        self._deallocated = val
        self.deallocated_at = None
        if val:
            self.deallocated_at = timeutils.utcnow()
            self.allocated_at = None

    # TODO(jkoelker) update the expression to use the jointable as well
    @deallocated.expression
    def deallocated(cls):
        return IPAddress._deallocated

    def formatted(self):
        ip = netaddr.IPAddress(self.address_readable)
        if self.version == 4:
            return str(ip.ipv4())
        return str(ip.ipv6())

    deallocated_at = sa.Column(sa.DateTime(), index=True)


class Route(BASEV2, models.HasTenant, models.HasId, IsHazTags):
    __tablename__ = "quark_routes"
    cidr = sa.Column(sa.String(64))
    gateway = sa.Column(sa.String(64))
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey("quark_subnets.id",
                                                       ondelete="CASCADE"))


class DNSNameserver(BASEV2, models.HasTenant, models.HasId, IsHazTags):
    __tablename__ = "quark_dns_nameservers"
    ip = sa.Column(custom_types.INET())
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey("quark_subnets.id",
                                                       ondelete="CASCADE"))


class Subnet(BASEV2, models.HasId, IsHazTags):
    """Upstream model for IPs.

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
    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36), sa.ForeignKey('quark_networks.id'))
    _cidr = sa.Column(sa.String(64), nullable=False)
    tenant_id = sa.Column(sa.String(255), index=True)
    segment_id = sa.Column(sa.String(255), index=True)

    @hybrid.hybrid_property
    def cidr(self):
        return self._cidr

    @cidr.setter
    def cidr(self, val):
        self._cidr = val
        preip = netaddr.IPNetwork(val)
        self.ip_version = preip.version
        ip = netaddr.IPNetwork(val).ipv6()
        self.first_ip = ip.first
        self.last_ip = ip.last
        self.next_auto_assign_ip = self.first_ip

    @cidr.expression
    def cidr(cls):
        return Subnet._cidr

    first_ip = sa.Column(custom_types.INET())
    last_ip = sa.Column(custom_types.INET())
    ip_version = sa.Column(sa.Integer())
    next_auto_assign_ip = sa.Column(custom_types.INET())

    allocated_ips = orm.relationship(IPAddress,
                                     primaryjoin='and_(Subnet.id=='
                                     'IPAddress.subnet_id,'
                                     'IPAddress._deallocated != 1)')
    generated_ips = orm.relationship(IPAddress,
                                     primaryjoin='Subnet.id=='
                                     'IPAddress.subnet_id')
    routes = orm.relationship(Route, primaryjoin="Route.subnet_id==Subnet.id",
                              backref='subnet', cascade='delete')
    enable_dhcp = sa.Column(sa.Boolean(), default=False)
    dns_nameservers = orm.relationship(
        DNSNameserver,
        primaryjoin="DNSNameserver.subnet_id==Subnet.id",
        backref='subnet',
        cascade='delete')
    ip_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey("quark_ip_policy.id"))
    # Legacy data
    do_not_use = sa.Column(sa.Boolean(), default=False)


port_group_association_table = sa.Table(
    "quark_port_security_group_associations",
    BASEV2.metadata,
    sa.Column("port_id", sa.String(36),
              sa.ForeignKey("quark_ports.id")),
    sa.Column("group_id", sa.String(36),
              sa.ForeignKey("quark_security_groups.id")),
    **TABLE_KWARGS)


class SecurityGroupRule(BASEV2, models.HasId, models.HasTenant):
    __tablename__ = "quark_security_group_rules"
    id = sa.Column(sa.String(36), primary_key=True)
    group_id = sa.Column(sa.String(36),
                         sa.ForeignKey("quark_security_groups.id"),
                         nullable=False)
    direction = sa.Column(sa.String(10), nullable=False)
    ethertype = sa.Column(sa.Integer(), nullable=False)
    port_range_max = sa.Column(sa.Integer(), nullable=True)
    port_range_min = sa.Column(sa.Integer(), nullable=True)
    protocol = sa.Column(sa.Integer(), nullable=True)
    remote_ip_prefix = sa.Column(sa.String(255), nullable=True)
    remote_group_id = sa.Column(sa.String(36),
                                sa.ForeignKey("quark_security_groups.id"),
                                nullable=True)


class SecurityGroup(BASEV2, models.HasId):
    __tablename__ = "quark_security_groups"
    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(255), nullable=False)
    description = sa.Column(sa.String(255), nullable=False)
    join = "SecurityGroupRule.group_id==SecurityGroup.id"
    rules = orm.relationship(SecurityGroupRule, backref='group',
                             cascade='delete',
                             primaryjoin=join)
    tenant_id = sa.Column(sa.String(255), index=True)


class Port(BASEV2, models.HasTenant, models.HasId):
    __tablename__ = "quark_ports"
    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(255), index=True)
    admin_state_up = sa.Column(sa.Boolean(), default=True)
    network_id = sa.Column(sa.String(36), sa.ForeignKey("quark_networks.id"),
                           nullable=False)

    backend_key = sa.Column(sa.String(36), nullable=False)
    mac_address = sa.Column(sa.BigInteger())
    device_id = sa.Column(sa.String(255), nullable=False, index=True)
    device_owner = sa.Column(sa.String(255))
    bridge = sa.Column(sa.String(255))

    @declarative.declared_attr
    def ip_addresses(cls):
        primaryjoin = cls.id == port_ip_association_table.c.port_id
        secondaryjoin = (port_ip_association_table.c.ip_address_id ==
                         IPAddress.id)
        return orm.relationship(IPAddress, primaryjoin=primaryjoin,
                                secondaryjoin=secondaryjoin,
                                secondary=port_ip_association_table,
                                backref="ports",
                                order_by='IPAddress.allocated_at')

    @declarative.declared_attr
    def security_groups(cls):
        primaryjoin = cls.id == port_group_association_table.c.port_id
        secondaryjoin = (port_group_association_table.c.group_id ==
                         SecurityGroup.id)
        return orm.relationship(SecurityGroup, primaryjoin=primaryjoin,
                                secondaryjoin=secondaryjoin,
                                secondary=port_group_association_table,
                                backref="ports")

# Indices tailored specifically to get_instance_nw_info calls from nova
sa.Index("idx_ports_1", Port.__table__.c.device_id, Port.__table__.c.tenant_id)
sa.Index("idx_ports_2", Port.__table__.c.device_owner,
         Port.__table__.c.network_id)
sa.Index("idx_ports_3", Port.__table__.c.tenant_id)


class MacAddress(BASEV2, models.HasTenant):
    __tablename__ = "quark_mac_addresses"
    address = sa.Column(sa.BigInteger(), primary_key=True)
    mac_address_range_id = sa.Column(
        sa.String(36),
        sa.ForeignKey("quark_mac_address_ranges.id", ondelete="CASCADE"),
        nullable=False)
    deallocated = sa.Column(sa.Boolean(), index=True)
    deallocated_at = sa.Column(sa.DateTime(), index=True)
    orm.relationship(Port, backref="mac_address")


class MacAddressRange(BASEV2, models.HasId):
    __tablename__ = "quark_mac_address_ranges"
    cidr = sa.Column(sa.String(255), nullable=False)
    first_address = sa.Column(sa.BigInteger(), nullable=False)
    last_address = sa.Column(sa.BigInteger(), nullable=False)
    next_auto_assign_mac = sa.Column(sa.BigInteger(), nullable=False)
    allocated_macs = orm.relationship(MacAddress,
                                      primaryjoin='and_(MacAddressRange.id=='
                                      'MacAddress.mac_address_range_id, '
                                      'MacAddress.deallocated!=1)',
                                      backref="mac_address_range")
    do_not_use = sa.Column(sa.Boolean(), default=False, nullable=False,
                           server_default='0')


class IPPolicy(BASEV2, models.HasId, models.HasTenant):
    __tablename__ = "quark_ip_policy"
    networks = orm.relationship(
        "Network",
        primaryjoin="IPPolicy.id==Network.ip_policy_id",
        backref="ip_policy")
    subnets = orm.relationship(
        "Subnet",
        primaryjoin="IPPolicy.id==Subnet.ip_policy_id",
        backref="ip_policy")
    exclude = orm.relationship(
        "IPPolicyCIDR",
        primaryjoin="IPPolicy.id==IPPolicyCIDR.ip_policy_id",
        backref="ip_policy")
    name = sa.Column(sa.String(255), nullable=True)
    description = sa.Column(sa.String(255), nullable=True)
    size = sa.Column(custom_types.INET())

    @staticmethod
    def get_ip_policy_cidrs(subnet):
        ip_policy = subnet["ip_policy"] or {}
        ip_policies = ip_policy.get("exclude", [])
        ip_policy_cidrs = [ip_policy_cidr.cidr
                           for ip_policy_cidr in ip_policies]
        return netaddr.IPSet(ip_policy_cidrs)


class IPPolicyCIDR(BASEV2, models.HasId):
    __tablename__ = "quark_ip_policy_cidrs"
    ip_policy_id = sa.Column(sa.String(36), sa.ForeignKey(
        "quark_ip_policy.id", ondelete="CASCADE"))
    cidr = sa.Column(sa.String(64))
    first_ip = sa.Column(custom_types.INET())
    last_ip = sa.Column(custom_types.INET())


class Network(BASEV2, models.HasId):
    __tablename__ = "quark_networks"
    name = sa.Column(sa.String(255))
    ports = orm.relationship(Port, backref='network')
    subnets = orm.relationship(Subnet, backref='network')
    ip_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey("quark_ip_policy.id"))
    network_plugin = sa.Column(sa.String(36))
    ipam_strategy = sa.Column(sa.String(255))
    tenant_id = sa.Column(sa.String(255), index=True)
