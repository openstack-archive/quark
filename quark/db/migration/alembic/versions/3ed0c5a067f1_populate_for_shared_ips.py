"""Populate enabled and do_not_use

Revision ID: 3ed0c5a067f1
Revises: 5927940a466e
Create Date: 2014-07-07 07:52:27.989294

"""

# revision identifiers, used by Alembic.
revision = '3ed0c5a067f1'
down_revision = '5927940a466e'

from alembic import op
from sqlalchemy.sql import column, table
import sqlalchemy as sa


def upgrade():
    port_ip_associations = table('quark_port_ip_address_associations',
                                 column('enabled', sa.Boolean()))
    mac_addr_ranges = table('quark_mac_address_ranges',
                            column('do_not_use', sa.Boolean()))

    connection = op.get_bind()

    a = port_ip_associations.update().values({'enabled': True})
    connection.execute(a)

    b = mac_addr_ranges.update().values({'do_not_use': False})
    connection.execute(b)


def downgrade():
    pass
