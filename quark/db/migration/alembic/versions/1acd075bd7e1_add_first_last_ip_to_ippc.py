"""Add first, last IP to IPPolicyCIDR

Revision ID: 1acd075bd7e1
Revises: 28e55acaf366
Create Date: 2014-08-07 06:52:39.575301

"""

# revision identifiers, used by Alembic.
revision = '1acd075bd7e1'
down_revision = '28e55acaf366'

from alembic import op
import sqlalchemy as sa

from quark.db.custom_types import INET


def upgrade():
    op.add_column('quark_ip_policy_cidrs',
                  sa.Column('first_ip', INET(), nullable=True))
    op.add_column('quark_ip_policy_cidrs',
                  sa.Column('last_ip', INET(), nullable=True))


def downgrade():
    op.drop_column('quark_ip_policy_cidrs', 'last_ip')
    op.drop_column('quark_ip_policy_cidrs', 'first_ip')
