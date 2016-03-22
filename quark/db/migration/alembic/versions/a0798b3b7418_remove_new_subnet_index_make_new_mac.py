"""remove new subnet index make new mac

Revision ID: a0798b3b7418
Revises: 80419263930a
Create Date: 2016-02-09 19:26:27.899610

"""

# revision identifiers, used by Alembic.
revision = 'a0798b3b7418'
down_revision = '80419263930a'

from alembic import op


def upgrade():
    op.drop_index(op.f('ix_quark_subnets_segement_network_version'),
                  table_name='quark_subnets')
    op.drop_index(op.f('ix_quark_mac_addresses_reallocation'),
                  table_name='quark_mac_addresses')
    op.create_index(op.f('ix_quark_mac_addresses_reallocation'),
                    'quark_mac_addresses', ['deallocated', 'deallocated_at'],
                    unique=False)


def downgrade():
    op.drop_index(op.f('ix_quark_mac_addresses_reallocation'),
                  table_name='quark_mac_addresses')
    op.create_index(op.f('ix_quark_mac_addresses_reallocation'),
                    'quark_mac_addresses', ['deallocated_at', 'deallocated'],
                    unique=False)
    op.create_index(op.f('ix_quark_subnets_segement_network_version'),
                    'quark_subnets', ['segment_id', 'network_id',
                                      'ip_version', 'do_not_use'],
                    unique=False)
