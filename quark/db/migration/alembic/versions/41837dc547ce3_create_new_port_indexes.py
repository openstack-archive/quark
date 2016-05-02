"""Create new port indexes

Revision ID: 41837dc547ce3
Revises: 3f0c11478a5d
Create Date: 2016-05-02 00:00:00

"""

# revision identifiers, used by Alembic.
revision = '41837dc547ce3'
down_revision = '3f0c11478a5d'

from alembic import op


def upgrade():
    op.create_index(op.f('ix_quark_ports_network_id_device_id'),
                    'quark_ports', ['network_id', 'device_id'])
    op.create_index(op.f('ix_quark_ports_device_id'),
                    'quark_ports', ['device_id'])


def downgrade():
    op.drop_index(op.f('ix_quark_ports_device_id'), table_name='quark_ports')
    op.drop_index(op.f('ix_quark_ports_network_id_device_id'),
                  table_name='quark_ports')
