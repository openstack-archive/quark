"""Truncate IPPolicyCIDR outside of Subnet._cidr

Revision ID: 2748e48cee3a
Revises: 4358d1b8cc75
Create Date: 2014-06-27 05:46:09.430767

"""

# revision identifiers, used by Alembic.
revision = '2748e48cee3a'
down_revision = '1284c81cf727'

import logging

from alembic import op
from sqlalchemy.sql import column, select, table
import netaddr
from oslo_utils import timeutils
from oslo_utils import uuidutils
import sqlalchemy as sa

LOG = logging.getLogger("alembic.migration")


def upgrade():
    ip_policy_cidrs = table('quark_ip_policy_cidrs',
                            column('id', sa.String(length=36)),
                            column('created_at', sa.DateTime()),
                            column('ip_policy_id', sa.String(length=36)),
                            column('cidr', sa.String(length=64)))
    subnets = table('quark_subnets',
                    column('_cidr', sa.String(length=64)),
                    column('ip_policy_id', sa.String(length=36)))

    connection = op.get_bind()

    # 1. Find `quark_ip_policy_cidrs` rows.
    data = connection.execute(select([
        subnets.c.ip_policy_id, subnets.c._cidr,
        ip_policy_cidrs.c.id, ip_policy_cidrs.c.cidr]).where(
            subnets.c.ip_policy_id == ip_policy_cidrs.c.ip_policy_id).order_by(
                subnets.c.ip_policy_id)).fetchall()
    if data is None:
        return

    # 2. Accumulate with `quark_ip_policy_cidrs` rows are outside of the
    #    subnet's cidr.
    ipp_to_update = dict()

    def _test_change_needed(ipp_id, s, ipp):
        if s is None or ipp is None:
            return
        diff = ipp - s
        if diff.size > 0:
            ipp_to_update[ipp_id] = ipp & s

    prev_ip_policy_id = ''
    subnet, ip_policy = None, None
    for ip_policy_id, cidr, ippc_id, ippc_cidr in data:
        if ip_policy_id != prev_ip_policy_id:
            _test_change_needed(prev_ip_policy_id, subnet, ip_policy)
            subnet, ip_policy = netaddr.IPSet([cidr]), netaddr.IPSet()
        ip_policy |= netaddr.IPSet([ippc_cidr])
        prev_ip_policy_id = ip_policy_id
    _test_change_needed(prev_ip_policy_id, subnet, ip_policy)

    if not ipp_to_update.keys():
        return

    LOG.info("IP Policy IDs to update: %s", ipp_to_update.keys())

    # 3. Delete `quark_ip_policy_cidrs` rows that need to be replaced with rows
    #    that are inside of the subnet's cidr.
    connection.execute(ip_policy_cidrs.delete().where(
        ip_policy_cidrs.c.ip_policy_id.in_(ipp_to_update.keys())))

    # 4. Insert `quark_ip_policy_cidrs` rows with cidrs that are inside the
    #    subnet's cidr.
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
