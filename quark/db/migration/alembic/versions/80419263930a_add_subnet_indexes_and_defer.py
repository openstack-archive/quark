"""add subnet indexes and defer

Revision ID: 80419263930a
Revises: 1bd7cff90384
Create Date: 2016-02-09 19:26:27.899610

"""

# revision identifiers, used by Alembic.
revision = '80419263930a'
down_revision = '1bd7cff90384'

from alembic import op


def upgrade():
    op.create_index(op.f('ix_quark_subnets_segement_network_version'),
                    'quark_subnets', ['segment_id', 'network_id',
                                      'ip_version', 'do_not_use'],
                    unique=False)


def downgrade():
    op.drop_index(op.f('ix_quark_subnets_segement_network_version'),
                  table_name='quark_subnets')
