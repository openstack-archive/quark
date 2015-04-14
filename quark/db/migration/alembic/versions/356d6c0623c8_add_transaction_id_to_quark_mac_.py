"""Add transaction_id to quark_mac_addresses

Revision ID: 356d6c0623c8
Revises: 5632aa202d89
Create Date: 2015-04-14 01:53:48.233241

"""

# revision identifiers, used by Alembic.
revision = '356d6c0623c8'
down_revision = '5632aa202d89'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('quark_mac_addresses',
                  sa.Column('transaction_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_quark_macs_transaction_id',
        'quark_mac_addresses', 'quark_transactions',
        ['transaction_id'], ['id'])


def downgrade():
    op.drop_constraint(
        'fk_quark_macs_transaction_id', 'quark_mac_addresses',
        type_='foreignkey')
    op.drop_column('quark_mac_addresses', 'transaction_id')
