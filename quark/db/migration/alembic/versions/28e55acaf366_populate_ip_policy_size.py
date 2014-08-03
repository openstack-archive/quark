"""Populate IPPolicy.size

Revision ID: 28e55acaf366
Revises: 3d22de205729
Create Date: 2014-08-06 14:50:04.022331

"""

# revision identifiers, used by Alembic.
revision = '28e55acaf366'
down_revision = '3d22de205729'

from alembic import op
from sqlalchemy.sql import column, select, table
import netaddr
import sqlalchemy as sa

from quark.db.custom_types import INET


def upgrade():
    ip_policy = table('quark_ip_policy',
                      column('id', sa.String(length=36)),
                      column('size', INET()))
    ip_policy_cidrs = table('quark_ip_policy_cidrs',
                            column('ip_policy_id', sa.String(length=36)),
                            column('cidr', sa.String(length=64)))
    connection = op.get_bind()

    # 1. Retrieve all ip_policy_cidr rows.
    results = connection.execute(
        select([ip_policy_cidrs.c.ip_policy_id, ip_policy_cidrs.c.cidr])
    ).fetchall()

    # 2. Determine IPSet for each IP Policy.
    ipp = dict()
    for ip_policy_id, cidr in results:
        if ip_policy_id not in ipp:
            ipp[ip_policy_id] = netaddr.IPSet()
        ipp[ip_policy_id].add(cidr)

    # 3. Populate size for each IP Policy.
    for ip_policy_id in ipp:
        connection.execute(ip_policy.update().values(
            size=ipp[ip_policy_id].size).where(
                ip_policy.c.id == ip_policy_id))


def downgrade():
    raise NotImplementedError()
