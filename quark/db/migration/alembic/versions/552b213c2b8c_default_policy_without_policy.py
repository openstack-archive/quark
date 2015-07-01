"""Ensure default IP policy exists for subnets without IP policies

Revision ID: 552b213c2b8c
Revises: 45a07fac3d38
Create Date: 2014-07-25 15:07:07.418971

"""

# revision identifiers, used by Alembic.
revision = '552b213c2b8c'
down_revision = '45a07fac3d38'

import logging

from quark.plugin_modules import ip_policies

from alembic import op
from sqlalchemy.sql import column, select, table
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
                    column('id', sa.String(length=36)),
                    column('_cidr', sa.String(length=64)),
                    column('tenant_id', sa.String(length=255)),
                    column('ip_policy_id', sa.String(length=36)))

    connection = op.get_bind()

    # 1. Find all subnets without ip_policy.
    data = connection.execute(select([
        subnets.c.id, subnets.c._cidr, subnets.c.tenant_id]).where(
            subnets.c.ip_policy_id == None)).fetchall()  # noqa
    if not data:
        return

    LOG.info("Subnet IDs without IP policies: %s", [d[0] for d in data])

    # 2. Insert ip_policy rows with id.
    vals = [dict(id=uuidutils.generate_uuid(),
                 created_at=timeutils.utcnow(),
                 tenant_id=tenant_id)
            for id, cidr, tenant_id in data]

    LOG.info("IP Policy IDs to insert: %s", [v["id"] for v in vals])
    connection.execute(ip_policy.insert(), *vals)

    # 3. Insert default ip_policy_cidrs for those ip_policy's.
    vals2 = []
    for ((id, cidr, tenant_id), ip_policy) in zip(data, vals):
        cidrs = []
        ip_policies.ensure_default_policy(cidrs, [dict(cidr=cidr)])
        for cidr in cidrs:
            vals2.append(dict(id=uuidutils.generate_uuid(),
                              created_at=timeutils.utcnow(),
                              ip_policy_id=ip_policy["id"],
                              cidr=str(cidr)))

    LOG.info("IP Policy CIDR IDs to insert: %s", [v["id"] for v in vals2])
    connection.execute(ip_policy_cidrs.insert(), *vals2)

    # 4. Set ip_policy_id rows in quark_subnets.
    for ((id, cidr, tenant_id), ip_policy) in zip(data, vals):
        connection.execute(subnets.update().values(
            ip_policy_id=ip_policy["id"]).where(
                subnets.c.id == id))


def downgrade():
    raise NotImplementedError()
