"""indexaroo

Revision ID: 1bdc1b574beb
Revises: 79d90e62d88
Create Date: 2015-05-20 21:39:19.348638

"""

# revision identifiers, used by Alembic.
revision = '1bdc1b574beb'
down_revision = '79d90e62d88'

from alembic import op


def upgrade():
    op.create_index(op.f('ix_quark_networks_tenant_id'),
                    'quark_networks',
                    ['tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_networks_tenant_id_name'),
                    'quark_networks',
                    ['tenant_id', 'name'],
                    unique=False)
    op.create_index(op.f('ix_quark_subnets_tenant_id'),
                    'quark_subnets',
                    ['tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_subnets_network_id_tenant_id'),
                    'quark_subnets',
                    ['network_id', 'tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_subnets_network_id'),
                    'quark_subnets',
                    ['network_id'],
                    unique=False)
    op.create_index(op.f('ix_quotas_tenant_id'),
                    'quotas',
                    ['tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_ports_tenant_id'),
                    'quark_ports',
                    ['tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_ports_network_id_tenant_id'),
                    'quark_ports',
                    ['network_id', 'tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_ports_name_tenant_id'),
                    'quark_ports',
                    ['name', 'tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_mac_address_ranges_selection'),
                    'quark_mac_address_ranges',
                    ['next_auto_assign_mac', 'do_not_use'],
                    unique=False)
    op.create_index(op.f('ix_quark_mac_addresses_reallocation'),
                    'quark_mac_addresses',
                    ['deallocated_at', 'deallocated'],
                    unique=False)


def downgrade():
    op.drop_index(op.f('ix_quark_networks_tenant_id'),
                  table_name='quark_networks')
    op.drop_index(op.f('ix_quark_networks_tenant_id_name'),
                  table_name='quark_networks')

    op.drop_index(op.f('ix_quark_subnets_tenant_id'),
                  table_name='quark_subnets')
    op.drop_index(op.f('ix_quark_subnets_network_id_tenant_id'),
                  table_name='quark_subnets')
    op.drop_index(op.f('ix_quark_subnets_network_id'),
                  table_name='quark_subnets')

    op.drop_index(op.f('ix_quark_ports_tenant_id'),
                  table_name='ports')
    op.drop_index(op.f('ix_quark_ports_network_id_tenant_id'),
                  table_name='quark_ports')
    op.drop_index(op.f('ix_quark_ports_name_tenant_id'),
                  table_name='quark_ports')

    op.drop_index(op.f('ix_quotas_tenant_id'),
                  table_name='quotas')
    op.drop_index(op.f('ix_quark_mac_address_ranges_selection'),
                  table_name='quark_mac_address_ranges')
    op.drop_index(op.f('ix_quark_mac_addresses_reallocation'),
                  table_name='quark_mac_addresses')
