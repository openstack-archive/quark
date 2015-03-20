"""Add subnets pool cache

Revision ID: 4d3ed7925db3
Revises: 3a47813ce501
Create Date: 2015-03-16 20:46:30.752875

"""

# revision identifiers, used by Alembic.
revision = '4d3ed7925db3'
down_revision = '3a47813ce501'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('quark_subnets', sa.Column('_allocation_pool_cache',
                                             sa.Text(),
                                             nullable=True))


def downgrade():
    op.drop_column('quark_subnets', '_allocation_pool_cache')
