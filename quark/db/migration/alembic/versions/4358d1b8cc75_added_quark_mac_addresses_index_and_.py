"""Added quark_mac_addresses index and unique constraint

Revision ID: 4358d1b8cc75
Revises: 56326c29d553
Create Date: 2014-06-04 15:45:23.481298

"""

# revision identifiers, used by Alembic.
revision = '4358d1b8cc75'
down_revision = '1817eef6373c'

from alembic import op


def upgrade():
    op.create_index(op.f('ix_quark_mac_addresses_deallocated'),
                    'quark_mac_addresses',
                    ['deallocated'],
                    unique=False)


def downgrade():
    op.drop_index(op.f('ix_quark_mac_addresses_deallocated'),
                  table_name='quark_mac_addresses')
