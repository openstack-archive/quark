"""add_port_network_plugin

Revision ID: 374c1bdb4480
Revises: 4da4444d7706
Create Date: 2015-10-20 12:08:24.780056

"""

# revision identifiers, used by Alembic.
revision = '374c1bdb4480'
down_revision = '4da4444d7706'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('quark_ports', sa.Column('network_plugin',
                  sa.String(length=36), nullable=True))


def downgrade():
    op.drop_column('quark_ports', 'network_plugin')
