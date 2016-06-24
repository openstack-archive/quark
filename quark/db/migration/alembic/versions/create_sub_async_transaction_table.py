"""create sub async transaction table
Revision ID: da46a8b30bd8
Revises: 271cce54e15b
Create Date: 2016-08-12 09:24:29.941684

"""

# revision identifiers, used by Alembic.
revision = 'da46a8b30bd8'
down_revision = '271cce54e15b'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('quark_async_transactions',
                  sa.Column('status', sa.String(255), nullable=True))
    op.add_column('quark_async_transactions',
                  sa.Column('resource_id', sa.String(255), nullable=True))
    op.add_column('quark_async_transactions',
                  sa.Column('transaction_id', sa.String(255), nullable=True))
    op.add_column('quark_async_transactions',
                  sa.Column('parent_task_id', sa.String(255), nullable=True))


def downgrade():
    op.drop_table('quark_async_subtransactions')
    op.drop_column('quark_async_transactions', 'resource_id')
    op.drop_column('quark_async_transactions', 'status')
