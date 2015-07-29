"""Move service column to association

Revision ID: 4dbf83f37bc0
Revises: 33e9e23ba761
Create Date: 2015-05-26 13:27:38.995202

"""

# revision identifiers, used by Alembic.
revision = '5932938bb839'
down_revision = '4dbf83f37bc0'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_column('quark_ports', 'service')
    op.add_column('quark_port_ip_address_associations',
                  sa.Column('service', sa.String(length=255),
                            nullable=False, server_default="none"))


def downgrade():
    op.drop_column('quark_port_ip_address_associations', 'service')
    op.add_column('quark_ports', sa.Column('service', sa.String(length=255),
                                           nullable=False,
                                           server_default="none"))
