"""Added Floating IP to Fixed IP mapping table

Revision ID: 33e9e23ba761
Revises: 356d6c0623c8
Create Date: 2015-05-11 14:14:23.619952

"""

# revision identifiers, used by Alembic.
revision = '33e9e23ba761'
down_revision = '356d6c0623c8'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('quark_floating_to_fixed_ip_address_associations',
                    sa.Column('floating_ip_address_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('fixed_ip_address_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('enabled', sa.Boolean(), server_default='1',
                              nullable=False),
                    sa.ForeignKeyConstraint(['fixed_ip_address_id'],
                                            ['quark_ip_addresses.id'], ),
                    sa.ForeignKeyConstraint(['floating_ip_address_id'],
                                            ['quark_ip_addresses.id'], ),
                    sa.PrimaryKeyConstraint('floating_ip_address_id',
                                            'fixed_ip_address_id'),
                    mysql_engine='InnoDB')


def downgrade():
    op.drop_table('quark_floating_to_fixed_ip_address_associations')
