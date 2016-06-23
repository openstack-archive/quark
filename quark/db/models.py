# Copyright 2013 Rackspace Hosting Inc.
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

import json

import netaddr
# NOTE(asadoughi): noqa import lines fix neutron DB changes breaking tests
from neutron.db import agentschedulers_db  # noqa
import neutron.db.model_base
from neutron.db import models_v2 as models
from neutron.db.qos import models as qos_models  # noqa
from neutron.db import rbac_db_models  # noqa
from neutron.db import segments_db  # noqa
from oslo_log import log as logging
from oslo_utils import timeutils
import sqlalchemy as sa
from sqlalchemy.ext import associationproxy
from sqlalchemy.ext import declarative
from sqlalchemy.ext import hybrid
from sqlalchemy import orm

from quark.db import custom_types
from quark.db import ip_types
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


class PortIpAssociation(object):
    pass


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
    sa.Column("service", sa.String(255), default='none', nullable=True,
              server_default='none'),
    **TABLE_KWARGS)


orm.mapper(PortIpAssociation, port_ip_association_table)


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
    network = orm.relationship("Network")
    version = sa.Column(sa.Integer(), index=True)
    allocated_at = sa.Column(sa.DateTime())
    subnet = orm.relationship("Subnet")
    # Need a constant to facilitate the indexed search for new IPs
    _deallocated = sa.Column(sa.Boolean())
    # Legacy data
    used_by_tenant_id = sa.Column(sa.String(255))

    address_type = sa.Column(sa.Enum(ip_types.FIXED, ip_types.FLOATING,
                                     ip_types.SHARED, ip_types.SCALING,
                             name="quark_ip_address_types"))
    associations = orm.relationship(PortIpAssociation, backref="ip_address")
    transaction_id = sa.Column(sa.Integer(),
                               sa.ForeignKey("quark_transactions.id"),
                               nullable=True)
    lock_id = sa.Column(sa.Integer(),
                        sa.ForeignKey("quark_locks.id"),
                        nullable=True)

    def is_shared(self):
        return self.address_type == ip_types.SHARED

    def has_any_shared_owner(self):
        for assoc in self["associations"]:
            if assoc.service != 'none' and assoc.service is not None:
                return True
        return False

    def set_service_for_port(self, port, service):
        for assoc in self["associations"]:
            if assoc.port_id == port["id"]:
                assoc.service = service

    def get_service_for_port(self, port):
        for assoc in self["associations"]:
            if assoc.port_id == port["id"]:
                return assoc.service

    def enabled_for_port(self, port):
        for assoc in self["associations"]:
            if assoc.port_id == port["id"]:
                return assoc.enabled

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
    fixed_ip = None


class FloatingToFixedIPAssociation(object):
    pass

flip_to_fixed_ip_assoc_tbl = sa.Table(
    "quark_floating_to_fixed_ip_address_associations",
    BASEV2.metadata,
    sa.Column("floating_ip_address_id", sa.String(36),
              sa.ForeignKey("quark_ip_addresses.id"), nullable=False,
              primary_key=True),
    sa.Column("fixed_ip_address_id", sa.String(36),
              sa.ForeignKey("quark_ip_addresses.id"), nullable=False,
              primary_key=True),
    sa.Column("enabled", sa.Boolean(), default=True, nullable=False,
              server_default='1'),
    **TABLE_KWARGS)

orm.mapper(FloatingToFixedIPAssociation, flip_to_fixed_ip_assoc_tbl)

IPAddress.fixed_ips = orm.relationship(
    "IPAddress", secondary=flip_to_fixed_ip_assoc_tbl,
    primaryjoin=(IPAddress.id == flip_to_fixed_ip_assoc_tbl
                 .c.floating_ip_address_id and flip_to_fixed_ip_assoc_tbl
                 .c.floating_ip_address_id == 1),
    secondaryjoin=(IPAddress.id == flip_to_fixed_ip_assoc_tbl
                   .c.fixed_ip_address_id), uselist=True)


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


def _pools_from_cidr(cidr):
    cidrs = cidr.iter_cidrs()
    if len(cidrs) == 0:
        return []
    if len(cidrs) == 1:
        return [dict(start=str(cidrs[0][0]),
                     end=str(cidrs[0][-1]))]

    pool_start = cidrs[0][0]
    prev_cidr_end = cidrs[0][-1]
    pools = []
    for cidr in cidrs[1:]:
        cidr_start = cidr[0]
        if prev_cidr_end + 1 != cidr_start:
            pools.append(dict(start=str(pool_start),
                              end=str(prev_cidr_end)))
            pool_start = cidr_start
        prev_cidr_end = cidr[-1]
    pools.append(dict(start=str(pool_start), end=str(prev_cidr_end)))
    return pools


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
    _allocation_pool_cache = orm.deferred(sa.Column(sa.Text(), nullable=True))
    tenant_id = sa.Column(sa.String(255), index=True)
    segment_id = sa.Column(sa.String(255), index=True)

    @hybrid.hybrid_property
    def cidr(self):
        return self._cidr

    @hybrid.hybrid_property
    def allocation_pools(self):
        _cache = self.get("_allocation_pool_cache")
        if _cache:
            pools = json.loads(_cache)
            return pools
        else:
            if self["ip_policy"]:
                ip_policy_cidrs = self["ip_policy"].get_cidrs_ip_set()
            else:
                ip_policy_cidrs = netaddr.IPSet([])

            cidr = netaddr.IPSet([netaddr.IPNetwork(self["cidr"])])
            allocatable = cidr - ip_policy_cidrs
            pools = _pools_from_cidr(allocatable)
            return pools

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


class Port(BASEV2, models.HasTenant, models.HasId, IsHazTags):
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
    associations = orm.relationship(PortIpAssociation, backref="port")

    network_plugin = sa.Column(sa.String(36), nullable=True)

    @declarative.declared_attr
    def ip_addresses(cls):
        primaryjoin = cls.id == port_ip_association_table.c.port_id
        secondaryjoin = (port_ip_association_table.c.ip_address_id ==
                         IPAddress.id)
        return orm.relationship(IPAddress, primaryjoin=primaryjoin,
                                secondaryjoin=secondaryjoin,
                                secondary=port_ip_association_table,
                                backref='ports',
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
    transaction_id = sa.Column(sa.Integer(),
                               sa.ForeignKey("quark_transactions.id"),
                               nullable=True)


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

    def get_cidrs_ip_set(self):
        ip_policies = self.get("exclude", [])
        ip_policy_cidrs = [ip_policy.cidr for ip_policy in ip_policies]
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


class Transaction(BASEV2):
    __tablename__ = "quark_transactions"
    id = sa.Column(sa.Integer, primary_key=True)


class Lock(BASEV2):
    __tablename__ = "quark_locks"
    id = sa.Column(sa.Integer, primary_key=True)
    type = sa.Column(sa.Enum("ip_address"), nullable=False)


class LockHolder(BASEV2):
    __tablename__ = "quark_lock_holders"
    id = sa.Column(sa.Integer, primary_key=True)
    lock_id = sa.Column(sa.Integer(),
                        sa.ForeignKey("quark_locks.id"),
                        nullable=False)
    name = sa.Column(sa.String(255), nullable=True)


class SegmentAllocation(BASEV2):
    """A segment allocation."""
    __tablename__ = "quark_segment_allocations"

    # a particular segment id is unique across the segment and type - this data
    # is denormalized to give us some safety around allocations, as well
    # as allow us to look up allocations to reallocate without a join.
    id = sa.Column(sa.BigInteger(), primary_key=True, autoincrement=False)
    segment_id = sa.Column(sa.String(36), primary_key=True)
    segment_type = sa.Column(sa.String(36), primary_key=True)

    segment_allocation_range_id = sa.Column(
        sa.String(36),
        sa.ForeignKey("quark_segment_allocation_ranges.id",
                      ondelete="CASCADE"))

    network_id = sa.Column(sa.String(36), nullable=True)

    deallocated = sa.Column(sa.Boolean(), index=True)
    deallocated_at = sa.Column(sa.DateTime(), index=True)


class SegmentAllocationRange(BASEV2, models.HasId):
    """Ranges of space for segment ids available for allocation."""
    __tablename__ = "quark_segment_allocation_ranges"
    segment_id = sa.Column(sa.String(36), index=True)
    segment_type = sa.Column(sa.String(36), index=True)

    first_id = sa.Column(sa.BigInteger(), nullable=False)
    last_id = sa.Column(sa.BigInteger(), nullable=False)

    do_not_use = sa.Column(sa.Boolean(), default=False, nullable=False)


class AsyncTransactions(BASEV2, models.HasId):
    __tablename__ = "quark_async_transactions"
    tenant_id = sa.Column(sa.String(255), index=True)
    action = sa.Column(sa.String(255))
    completed = sa.Column(sa.Boolean(), default=False)
