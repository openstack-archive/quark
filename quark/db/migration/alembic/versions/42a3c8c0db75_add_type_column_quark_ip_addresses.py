"""add_type_column_quark_ip_addresses

Revision ID: 42a3c8c0db75
Revises: 3b467be51e43
Create Date: 2014-10-14 14:21:25.016371

"""

# revision identifiers, used by Alembic.
revision = '42a3c8c0db75'
down_revision = '3b467be51e43'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('quark_ip_addresses',
                  sa.Column('address_type',
                            sa.Enum('shared', 'floating', 'fixed',
                                    name='quark_ip_address_types'),
                            nullable=True))


def downgrade():
    op.drop_column('quark_ip_addresses', 'address_type')
