import sqlalchemy as sa
from sqlalchemy import orm

from quantum.db.model_base import BASEV2
from quantum.db.models_v2 import HasTenant, HasId


class CreatedAt(object):
    created_at = sa.Column(sa.DateTime())


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
    """More closely the melange version of the IP table.
    We always mark the record as deallocated rather than deleting it.
    Gives us an IP address owner audit log for free, essentially"""

    __tablename__ = "quark_ip_addresses"

    address = sa.Column(sa.String(64), nullable=False)
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey("quark_subnets.id",
                                        ondelete="CASCADE"))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("quark_networks.id",
                                         ondelete="CASCADE"))
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey("quark_ports.id", ondelete="CASCADE"))

    # Need a constant to facilitate the indexed search for new IPs
    deallocated = sa.Column(sa.Boolean())
    deallocated_at = sa.Column(sa.DateTime())


class Route(BASEV2, CreatedAt, HasId):
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
    cidr = sa.Column(sa.String(64), nullable=False)
    # TODO(mdietz): re-add this later if possible
    allocated_ips = orm.relationship(IPAddress, backref="subnet",
                                     lazy="select")

                                     #, cascade="DELETE")
    routes = orm.relationship(Route,
                              backref='subnet',
                              cascade='delete', lazy="select")


class MacAddress(BASEV2, CreatedAt, HasTenant):
    __tablename__ = "quark_mac_addresses"
    address = sa.Column(sa.Integer(), primary_key=True)
    mac_address_range_id = sa.Column(sa.Integer(),
                                sa.ForeignKey("quark_mac_address_ranges.id"),
                                nullable=False)


class MacAddressRange(BASEV2, CreatedAt, HasId):
    __tablename__ = "quark_mac_address_ranges"
    cidr = sa.Column(sa.String(255), nullable=False)


class Port(BASEV2, CreatedAt, HasId, HasTenant):
    __tablename__ = "quark_ports"
    network_id = sa.Column(sa.String(36), sa.ForeignKey("quark_networks.id"),
                           nullable=False)

    # Maybe have this for optimizing lookups.
    # subnet_id = sa.Column(sa.String(36), sa.ForeignKey("subnets.id"),
    #                      nulllable=False)
    mac_address = sa.Column(sa.Integer(),
                            sa.ForeignKey("quark_mac_addresses.address"))

    # device is an ID pertaining to the entity utilizing the port. Could be
    # an instance, a load balancer, or any other network capable object
    device_id = sa.Column(sa.String(255), nullable=False)


class Network(BASEV2, CreatedAt, HasTenant, HasId):
    __tablename__ = "quark_networks"
    name = sa.Column(sa.String(255))
    ports = orm.relationship(Port, backref='network')
    subnets = orm.relationship(Subnet, backref='network')
