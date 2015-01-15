"""quark_ports.created_at index for pagination sorting

Revision ID: 3a47813ce501
Revises: 4fc07b41d45c
Create Date: 2015-01-14 16:15:10.938745

"""

# revision identifiers, used by Alembic.
revision = '3a47813ce501'
down_revision = '4fc07b41d45c'

from alembic import op


def upgrade():
    op.create_index(op.f('ix_quark_ports_created_at'),
                    'quark_ports',
                    ['created_at'],
                    unique=False)


def downgrade():
        op.drop_index(op.f('ix_quark_ports_created_at'),
                      table_name='quark_ports')
