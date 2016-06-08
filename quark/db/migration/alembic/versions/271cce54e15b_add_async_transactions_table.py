"""Add async transactions table

Revision ID: 271cce54e15b
Revises: 2a116b962c95
Create Date: 2016-06-15 09:24:29.941684

"""

# revision identifiers, used by Alembic.
revision = '271cce54e15b'
down_revision = '2a116b962c95'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('quark_async_transactions',
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('id', sa.String(36), nullable=False),
                    sa.Column('tenant_id', sa.String(255), nullable=False),
                    sa.Column('action', sa.String(255), nullable=False),
                    sa.Column('completed', sa.Boolean()),
                    sa.PrimaryKeyConstraint('id'),
                    mysql_engine='InnoDB')
    op.create_index(op.f('ix_quark_async_transactions_tenant_id'),
                    'quark_async_transactions', ['tenant_id'],
                    unique=False)


def downgrade():
    op.drop_table('quark_async_transactions')
