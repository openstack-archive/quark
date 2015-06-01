"""indexapalooza

Revision ID: 79d90e62d88
Revises: 33e9e23ba761
Create Date: 2015-05-20 20:52:01.909161

"""

# revision identifiers, used by Alembic.
revision = '79d90e62d88'
down_revision = '33e9e23ba761'

from alembic import op


def upgrade():
    op.drop_index(op.f('ix_quark_ip_addresses_version'),
                  table_name='quark_ip_addresses')
    op.drop_index(op.f('ix_quark_ip_addresses_deallocated_at'),
                  table_name='quark_ip_addresses')
    op.drop_index(op.f('ix_quark_ip_addresses_address'),
                  table_name='quark_ip_addresses')
    op.drop_index(op.f('ix_quark_subnets_tenant_id'),
                  table_name='quark_subnets')
    op.drop_index(op.f('ix_quark_subnets_segment_id'),
                  table_name='quark_subnets')
    op.drop_index(op.f('ix_quark_ports_name'), table_name='quark_ports')
    op.drop_index(op.f('ix_quark_ports_device_id'), table_name='quark_ports')
    op.drop_index('idx_ports_3', table_name='quark_ports')
    op.drop_index('idx_ports_2', table_name='quark_ports')
    op.drop_index('idx_ports_1', table_name='quark_ports')
    op.drop_index(op.f('ix_quark_networks_tenant_id'),
                  table_name='quark_networks')
    op.drop_index(op.f('ix_quark_mac_addresses_deallocated_at'),
                  table_name='quark_mac_addresses')
    op.drop_index(op.f('ix_quark_security_groups_tenant_id'),
                  table_name='quark_security_groups')
    op.drop_index(op.f('ix_quark_nvp_driver_lswitchport_port_id'),
                  table_name='quark_nvp_driver_lswitchport')
    op.drop_index(op.f('ix_quark_nvp_driver_security_profile_nvp_id'),
                  table_name='quark_nvp_driver_security_profile')
    op.drop_index(op.f('ix_quark_nvp_driver_lswitch_nvp_id'),
                  table_name='quark_nvp_driver_lswitch')
    op.drop_index(op.f('ix_quark_nvp_driver_lswitch_network_id'),
                  table_name='quark_nvp_driver_lswitch')
    op.drop_index(op.f('ix_quotas_tenant_id'), table_name='quotas')
    op.drop_index(op.f('ix_quark_nvp_orphaned_lswitches_nvp_id'),
                  table_name='quark_nvp_orphaned_lswitches')
    op.drop_index(op.f('ix_quark_nvp_orphaned_lswitches_network_id'),
                  table_name='quark_nvp_orphaned_lswitches')
    op.drop_index(op.f('ix_quark_nvp_orphaned_lswitches_display_name'),
                  table_name='quark_nvp_orphaned_lswitches')
    op.drop_index(op.f('ix_quark_nvp_orphaned_lswitch_ports_port_id'),
                  table_name='quark_nvp_orphaned_lswitch_ports')
    op.drop_index(op.f('ix_quark_ports_created_at'),
                  table_name='quark_ports')
    op.drop_index(op.f('ix_quark_mac_addresses_deallocated'),
                  table_name='quark_mac_addresses')


def downgrade():
    op.create_index(op.f('ix_quark_security_groups_tenant_id'),
                    'quark_security_groups',
                    ['tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_mac_addresses_deallocated_at'),
                    'quark_mac_addresses',
                    ['deallocated_at'],
                    unique=False)
    op.create_index(op.f('ix_quark_networks_tenant_id'),
                    'quark_networks',
                    ['tenant_id'],
                    unique=False)
    op.create_index('idx_ports_1',
                    'quark_ports',
                    ['device_id', 'tenant_id'],
                    unique=False)
    op.create_index('idx_ports_2',
                    'quark_ports',
                    ['device_owner', 'network_id'],
                    unique=False)
    op.create_index('idx_ports_3', 'quark_ports', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_quark_ports_device_id'),
                    'quark_ports',
                    ['device_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_ports_name'), 'quark_ports', ['name'],
                    unique=False)
    op.create_index(op.f('ix_quark_subnets_segment_id'),
                    'quark_subnets',
                    ['segment_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_subnets_tenant_id'),
                    'quark_subnets',
                    ['tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_subnets_tenant_id'),
                    'quark_subnets',
                    ['tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_ip_addresses_address'),
                    'quark_ip_addresses',
                    ['address'],
                    unique=False)
    op.create_index(op.f('ix_quark_ip_addresses_deallocated_at'),
                    'quark_ip_addresses',
                    ['deallocated_at'],
                    unique=False)
    op.create_index(op.f('ix_quark_ip_addresses_version'),
                    'quark_ip_addresses',
                    ['version'],
                    unique=False)
    op.create_index(op.f('ix_quark_ip_addresses_version'),
                    'quark_ip_addresses',
                    ['version'],
                    unique=False)
    op.create_index(op.f('ix_quotas_tenant_id'),
                    'quotas',
                    ['tenant_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_nvp_driver_lswitch_network_id'),
                    'quark_nvp_driver_lswitch',
                    ['network_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_nvp_driver_lswitch_nvp_id'),
                    'quark_nvp_driver_lswitch',
                    ['nvp_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_nvp_driver_security_profile_nvp_id'),
                    'quark_nvp_driver_security_profile',
                    ['nvp_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_nvp_driver_security_profile_nvp_id'),
                    'quark_nvp_driver_security_profile',
                    ['nvp_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_nvp_driver_lswitchport_port_id'),
                    'quark_nvp_driver_lswitchport',
                    ['port_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_nvp_orphaned_lswitches_nvp_id'),
                    'quark_nvp_orphaned_lswitches',
                    ['nvp_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_nvp_orphaned_lswitches_network_id'),
                    'quark_nvp_orphaned_lswitches',
                    ['network_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_nvp_orphaned_lswitches_display_name'),
                    'quark_nvp_orphaned_lswitches',
                    ['display_name'],
                    unique=False)
    op.create_index(op.f('ix_quark_nvp_orphaned_lswitch_ports_port_id'),
                    'quark_nvp_orphaned_lswitch_ports',
                    ['port_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_ports_created_at'),
                    'quark_ports',
                    ['created_at'],
                    unique=False)
    op.create_index(op.f('ix_quark_mac_addresses_deallocated'),
                    'quark_mac_addresses',
                    ['deallocated'],
                    unique=False)
