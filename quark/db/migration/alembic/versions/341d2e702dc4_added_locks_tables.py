"""Added locks tables

Revision ID: 341d2e702dc4
Revises: e249ebc4f51
Create Date: 2015-09-03 09:24:29.941684

"""

# revision identifiers, used by Alembic.
revision = '341d2e702dc4'
down_revision = 'e249ebc4f51'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('quark_locks',
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('type', sa.Enum('ip_address'), nullable=False),
                    sa.PrimaryKeyConstraint('id'),
                    mysql_engine='InnoDB')
    op.create_table('quark_lock_holders',
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('lock_id', sa.Integer(), nullable=False),
                    sa.Column('name', sa.String(length=255), nullable=True),
                    sa.ForeignKeyConstraint(['lock_id'], ['quark_locks.id'], ),
                    sa.PrimaryKeyConstraint('id'),
                    mysql_engine='InnoDB')
    op.add_column(u'quark_ip_addresses', sa.Column('lock_id', sa.Integer(),
                                                   nullable=True))


def downgrade():
    op.drop_column(u'quark_ip_addresses', 'lock_id')
    op.drop_table('quark_lock_holders')
    op.drop_table('quark_locks')
