"""Populate first_ip, last_ip for each IP Policy CIDR

Revision ID: 1664300cb03a
Revises: 1acd075bd7e1
Create Date: 2014-08-07 07:17:32.841155

"""

# revision identifiers, used by Alembic.
revision = '1664300cb03a'
down_revision = '1acd075bd7e1'

from alembic import op
import netaddr
from sqlalchemy.sql import column, select, table
import sqlalchemy as sa

from quark.db.custom_types import INET


def upgrade():
    ip_policy_cidrs = table('quark_ip_policy_cidrs',
                            column('id', sa.String(length=36)),
                            column('first_ip', INET()),
                            column('last_ip', INET()),
                            column('cidr', sa.String(length=64)))
    connection = op.get_bind()

    # 1. Retrieve all ip_policy_cidr rows.
    results = connection.execute(
        select([ip_policy_cidrs.c.id, ip_policy_cidrs.c.cidr])
    ).fetchall()

    # 2. Populate first_ip, last_ip for each IP Policy CIDR.
    for ippc in results:
        net = netaddr.IPNetwork(ippc["cidr"]).ipv6()
        connection.execute(ip_policy_cidrs.update().values(
            first_ip=net.first, last_ip=net.last).where(
                ip_policy_cidrs.c.id == ippc["id"]))


def downgrade():
    raise NotImplementedError()
