"""Added transactions table

Revision ID: 5632aa202d89
Revises: 3a47813ce501
Create Date: 2015-03-18 14:54:09.061787

"""

# revision identifiers, used by Alembic.
revision = '5632aa202d89'
down_revision = '4d3ed7925db3'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('quark_transactions',
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.PrimaryKeyConstraint('id'),
                    mysql_engine='InnoDB')
    op.add_column(u'quark_ip_addresses',
                  sa.Column('transaction_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_quark_ips_transaction_id',
                          'quark_ip_addresses',
                          'quark_transactions',
                          ['transaction_id'],
                          ['id'])


def downgrade():
    op.drop_constraint('fk_quark_ips_transaction_id', 'quark_ip_addresses',
                       type_='foreignkey')
    op.drop_column(u'quark_ip_addresses', 'transaction_id')
    op.drop_table('quark_transactions')
