"""Add size to quark_ip_policy

Revision ID: 3d22de205729
Revises: 2748e48cee3a
Create Date: 2014-07-04 23:53:09.531715

"""

# revision identifiers, used by Alembic.
revision = '3d22de205729'
down_revision = '3ed0c5a067f1'

from alembic import op
import sqlalchemy as sa

from quark.db.custom_types import INET


def upgrade():
    op.add_column('quark_ip_policy', sa.Column('size', INET()))


def downgrade():
    op.drop_column('quark_ip_policy', 'size')
