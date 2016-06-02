"""drop deallocated_at from mac addresses index

Revision ID: 2a116b962c95
Revises: 41837dc547ce3
Create Date: 2016-06-02 19:26:27.899610

"""

# revision identifiers, used by Alembic.
revision = '2a116b962c95'
down_revision = '41837dc547ce3'

from alembic import op


def upgrade():
    op.drop_index(op.f('ix_quark_mac_addresses_reallocation'),
                  table_name='quark_mac_addresses')
    op.create_index(op.f('ix_quark_mac_addresses_reallocation'),
                    'quark_mac_addresses', ['deallocated'],
                    unique=False)


def downgrade():
    op.drop_index(op.f('ix_quark_mac_addresses_reallocation'),
                  table_name='quark_mac_addresses')
    op.create_index(op.f('ix_quark_mac_addresses_reallocation'),
                    'quark_mac_addresses', ['deallocated', 'deallocated_at'],
                    unique=False)
