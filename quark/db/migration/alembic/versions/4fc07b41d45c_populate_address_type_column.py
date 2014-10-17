"""populate address_type column

Revision ID: 4fc07b41d45c
Revises: 42a3c8c0db75
Create Date: 2014-10-16 14:09:43.175030

"""

# revision identifiers, used by Alembic.
revision = '4fc07b41d45c'
down_revision = '42a3c8c0db75'

from alembic import op
from sqlalchemy.sql import table, column
import sqlalchemy as sa


def upgrade():
    ip_addresses = table('quark_ip_addresses',
                         column('address_type', sa.Enum),
                         column('_deallocated', sa.Boolean))
    connection = op.get_bind()
    t = ip_addresses.update().values({'address_type': 'fixed'}).where(
        ip_addresses.c._deallocated == 0)
    connection.execute(t)


def downgrade():
    ip_addresses = table('quark_ip_addresses',
                         column('address_type', sa.Enum))
    connection = op.get_bind()
    t = ip_addresses.update().values({'address_type': None})
    connection.execute(t)
