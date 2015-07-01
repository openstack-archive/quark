"""Ensure default IP policy for subnets with IP policies

Revision ID: 45a07fac3d38
Revises: 2748e48cee3a
Create Date: 2014-07-05 12:49:51.815631

"""

# revision identifiers, used by Alembic.
revision = '45a07fac3d38'
down_revision = '2748e48cee3a'

import logging

from alembic import op
from sqlalchemy.sql import column, select, table
import netaddr
from oslo_utils import timeutils
from oslo_utils import uuidutils
import sqlalchemy as sa

LOG = logging.getLogger("alembic.migration")


def upgrade():
    ip_policy = table('quark_ip_policy',
                      column('id', sa.String(length=36)),
                      column('tenant_id', sa.String(length=255)),
                      column('created_at', sa.DateTime()))
    ip_policy_cidrs = table('quark_ip_policy_cidrs',
                            column('id', sa.String(length=36)),
                            column('created_at', sa.DateTime()),
                            column('ip_policy_id', sa.String(length=36)),
                            column('cidr', sa.String(length=64)))
    subnets = table('quark_subnets',
                    column('_cidr', sa.String(length=64)),
                    column('ip_policy_id', sa.String(length=36)))

    connection = op.get_bind()

    # 1. Get all ip_policy_cidrs for subnets with an ip_policy.
    j = subnets.outerjoin(
        ip_policy_cidrs,
        subnets.c.ip_policy_id == ip_policy_cidrs.c.ip_policy_id)
    q = select([subnets.c.ip_policy_id, subnets.c._cidr,
                ip_policy_cidrs.c.id, ip_policy_cidrs.c.cidr]).select_from(
                    j).where(subnets.c.ip_policy_id != None).order_by(  # noqa
                        subnets.c.ip_policy_id)
    data = connection.execute(q).fetchall()
    if data is None:
        return

    # 2. Check ip_policy_cidrs contains default ip policy for subnet.
    ipp_to_update = dict()

    def _test_change_needed(ipp_id, s, ipp):
        if s is None or ipp is None:
            return
        updated = False
        last = netaddr.IPAddress(subnet.broadcast)
        first = netaddr.IPAddress(subnet.network)
        if last not in ipp:
            updated = True
            ipp.add(last)
        if first not in ipp:
            updated = True
            ipp.add(first)
        if updated:
            ipp_to_update[ipp_id] = ipp

    prev_ip_policy_id = ''
    subnet, ip_policy = None, None
    for ip_policy_id, cidr, ippc_id, ippc_cidr in data:
        if ip_policy_id != prev_ip_policy_id:
            _test_change_needed(prev_ip_policy_id, subnet, ip_policy)
            subnet, ip_policy = netaddr.IPNetwork(cidr), netaddr.IPSet()
        ip_policy |= netaddr.IPSet([ippc_cidr] if ippc_cidr else [])
        prev_ip_policy_id = ip_policy_id
    _test_change_needed(prev_ip_policy_id, subnet, ip_policy)

    if not ipp_to_update.keys():
        return

    LOG.info("IP Policy IDs to update: %s", ipp_to_update.keys())

    # 3. Delete ip_policy_cidrs for ip_policy_ids to be updated.
    connection.execute(ip_policy_cidrs.delete().where(
        ip_policy_cidrs.c.ip_policy_id.in_(ipp_to_update.keys())))

    # 4. Insert ip_policy_cidrs for ip_policy_ids to be updated.
    vals = [dict(id=uuidutils.generate_uuid(),
                 created_at=timeutils.utcnow(),
                 ip_policy_id=key,
                 cidr=str(x.cidr))
            for key in ipp_to_update.keys()
            for x in ipp_to_update[key].iter_cidrs()]
    if not vals:
        return

    LOG.info("IP Policy CIDR IDs to insert: %s", [v["id"] for v in vals])

    connection.execute(ip_policy_cidrs.insert(), *vals)


def downgrade():
    raise NotImplementedError()
