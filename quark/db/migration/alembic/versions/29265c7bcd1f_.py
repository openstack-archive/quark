"""empty message

Revision ID: 29265c7bcd1f
Revises: 4dbf83f37bc0
Create Date: 2015-06-18 14:27:18.571918

"""

# revision identifiers, used by Alembic.
revision = '29265c7bcd1f'
down_revision = '4dbf83f37bc0'

from alembic import op


def upgrade():
    op.create_index(op.f('ix_quark_reallocate_ip_addresses'),
                    'quark_ip_addresses',
                    ["network_id", "tenant_id", "version", "subnet_id",
                     "deallocated_at"],
                    unique=False)


def downgrade():
    op.drop_index(op.f('ix_quark_reallocate_ip_addresses'),
                  table_name='quark_ip_addresses')
