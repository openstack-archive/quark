import sqlalchemy as sa
from sqlalchemy import orm
from quantum.db import model_base
from quantum.db.models_v2 import HasTenant, HasId


# TODO(mdietz): discuss any IP reservation policies ala Melange with the nerds
# but not sure if we need them offhand


class ModelBase(model_base.BASEV2):
    created_at = sa.Column(sa.DateTime())


class IPAllocation(ModelBase, HasTenant):
    address = sa.Column(sa.String(64), nullable=False, primary_key=True)
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey("subnets.id", ondelete="CASCADE"),
                          primary_key=True)
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("networks.id", ondelete="CASCADE"),
                           primary_key=True)
    port_id = sa.Column(sa.Column(36),
                        sa.ForeignKey("ports.id", ondelete="CASCADE"))


class Route(ModelBase, HasId):
    cidr = sa.Column(sa.String(64))
    gateway = sa.Column(sa.String(64))
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey("subnets.id"))


class Subnet(ModelBase, HasId, HasTenant):
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

    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'))
    cidr = sa.Column(sa.String(64), nullable=False)
    allocated_ips = orm.relationship(IPAllocation, backref="subnet",
                                     lazy="dynamic", cascade="DELETE")
    routes = orm.relationship(Route,
                              backref='subnet',
                              cascade='delete')


class Port(ModelBase, HasId, HasTenant):
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id"),
                           nullable=False)

    # Maybe have this for optimizing lookups.
    # subnet_id = sa.Column(sa.String(36), sa.ForeignKey("subnets.id"),
    #                      nulllable=False)
    mac_address = sa.Column(sa.String(32), nullable=False)

    # device is an ID pertaining to the entity utilizing the port. Could be
    # an instance, a load balancer, or any other network capable object
    device_id = sa.Column(sa.String(255), nullable=False)


class Network(ModelBase, HasTenant, HasId):
    name = sa.Column(sa.String(255))
    ports = orm.relationship(Port, backref='networks')
    subnets = orm.relationship(Subnet, backref='networks')
