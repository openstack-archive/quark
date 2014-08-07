"""Create enabled and do_not_use columns

Revision ID: 5927940a466e
Revises: 552b213c2b8c
Create Date: 2014-07-07 07:50:39.372294

"""

# revision identifiers, used by Alembic.
revision = '5927940a466e'
down_revision = '552b213c2b8c'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('quark_port_ip_address_associations',
                  sa.Column('enabled',
                            sa.Boolean(),
                            nullable=False,
                            server_default='1'))
    op.add_column('quark_mac_address_ranges',
                  sa.Column('do_not_use',
                            sa.Boolean(),
                            nullable=False,
                            server_default='0'))


def downgrade():
    op.drop_column('quark_mac_address_ranges', 'do_not_use')
    op.drop_column('quark_port_ip_address_associations', 'enabled')
