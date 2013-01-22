import sqlalchemy as sa
#from sqlalchemy import orm
from quantum.db import model_base
from quantum.db import models_v2


class Network(model_base.BASEV2, models_v2.HasTenant, models_v2.HasId):
    name = sa.Column(sa.String(255))
    #ports = orm.relationship(Port, backref='networks')
    #subnets = orm.relationship(Subnet, backref='networks')


class Subnet(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'))
    cidr = sa.Column(sa.String(64), nullable=False)
    #allocation_pools = orm.relationship(IPAllocationPool,
    #                                    backref='subnet',
    #                                    lazy="dynamic",
    #                                    cascade='delete')
    #dns_nameservers = orm.relationship(DNSNameServer,
    #                                   backref='subnet',
    #                                   cascade='delete')
    #routes = orm.relationship(Route,
    #                          backref='subnet',
    #                          cascade='delete')
