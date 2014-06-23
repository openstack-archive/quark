"""Initial version

Revision ID: 1817eef6373c
Revises: None
Create Date: 2014-03-11 04:57:08.498604

"""

# revision identifiers, used by Alembic.
revision = '1817eef6373c'
down_revision = None

from alembic import op
import sqlalchemy as sa

from quark.db.custom_types import INET


def upgrade():
    op.create_table(
        'quark_mac_address_ranges',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('cidr', sa.String(length=255), nullable=False),
        sa.Column('first_address', sa.BigInteger(), nullable=False),
        sa.Column('last_address', sa.BigInteger(), nullable=False),
        sa.Column('next_auto_assign_mac', sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_tag_associations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('discriminator', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_ip_policy',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_security_groups',
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_index(
        op.f('ix_quark_security_groups_tenant_id'),
        'quark_security_groups',
        ['tenant_id'],
        unique=False)
    op.create_table(
        'quark_tags',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('association_uuid', sa.String(length=36), nullable=False),
        sa.Column('tag', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['association_uuid'],
                                [u'quark_tag_associations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_security_group_rule',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('group_id', sa.String(length=36), nullable=False),
        sa.Column('direction', sa.String(length=10), nullable=False),
        sa.Column('ethertype', sa.String(length=4), nullable=False),
        sa.Column('port_range_max', sa.Integer(), nullable=True),
        sa.Column('port_range_min', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.Integer(), nullable=True),
        sa.Column('remote_ip_prefix', sa.String(length=22), nullable=True),
        sa.Column('remote_group_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['group_id'], ['quark_security_groups.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_mac_addresses',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('address', sa.BigInteger(), nullable=False),
        sa.Column('mac_address_range_id', sa.String(length=36),
                  nullable=False),
        sa.Column('deallocated', sa.Boolean(), nullable=True),
        sa.Column('deallocated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['mac_address_range_id'],
                                ['quark_mac_address_ranges.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('address'),
        mysql_engine='InnoDB')
    op.create_index(
        op.f('ix_quark_mac_addresses_deallocated_at'),
        'quark_mac_addresses',
        ['deallocated_at'],
        unique=False)
    op.create_table(
        'quark_ip_policy_cidrs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('ip_policy_id', sa.String(length=36), nullable=True),
        sa.Column('cidr', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['ip_policy_id'],
                                ['quark_ip_policy.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_networks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('ip_policy_id', sa.String(length=36), nullable=True),
        sa.Column('network_plugin', sa.String(length=36), nullable=True),
        sa.Column('ipam_strategy', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['ip_policy_id'], ['quark_ip_policy.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_index(op.f('ix_quark_networks_tenant_id'),
                    'quark_networks',
                    ['tenant_id'],
                    unique=False)
    op.create_table(
        'quark_ports',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('backend_key', sa.String(length=36), nullable=False),
        sa.Column('mac_address', sa.BigInteger(), nullable=True),
        sa.Column('device_id', sa.String(length=255), nullable=False),
        sa.Column('device_owner', sa.String(length=255), nullable=True),
        sa.Column('bridge', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['quark_networks.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
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
    op.create_table(
        'quark_subnets',
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('_cidr', sa.String(length=64), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('segment_id', sa.String(length=255), nullable=True),
        sa.Column('first_ip', INET(), nullable=True),
        sa.Column('last_ip', INET(), nullable=True),
        sa.Column('ip_version', sa.Integer(), nullable=True),
        sa.Column('next_auto_assign_ip', INET(), nullable=True),
        sa.Column('enable_dhcp', sa.Boolean(), nullable=True),
        sa.Column('ip_policy_id', sa.String(length=36), nullable=True),
        sa.Column('do_not_use', sa.Boolean(), nullable=True),
        sa.Column('tag_association_uuid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['ip_policy_id'], ['quark_ip_policy.id'], ),
        sa.ForeignKeyConstraint(['network_id'], ['quark_networks.id'], ),
        sa.ForeignKeyConstraint(['tag_association_uuid'],
                                [u'quark_tag_associations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_index(
        op.f('ix_quark_subnets_segment_id'),
        'quark_subnets',
        ['segment_id'],
        unique=False)
    op.create_index(
        op.f('ix_quark_subnets_tenant_id'),
        'quark_subnets',
        ['tenant_id'],
        unique=False)
    op.create_table(
        'quark_routes',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('cidr', sa.String(length=64), nullable=True),
        sa.Column('gateway', sa.String(length=64), nullable=True),
        sa.Column('subnet_id', sa.String(length=36), nullable=True),
        sa.Column('tag_association_uuid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['subnet_id'], ['quark_subnets.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tag_association_uuid'],
                                [u'quark_tag_associations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_port_security_group_associations',
        sa.Column('port_id', sa.String(length=36), nullable=True),
        sa.Column('group_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['group_id'], ['quark_security_groups.id'], ),
        sa.ForeignKeyConstraint(['port_id'], ['quark_ports.id'], ),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_ip_addresses',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('address_readable', sa.String(length=128), nullable=False),
        sa.Column('address', INET(), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('version', sa.Integer(), nullable=True),
        sa.Column('allocated_at', sa.DateTime(), nullable=True),
        sa.Column('_deallocated', sa.Boolean(), nullable=True),
        sa.Column('used_by_tenant_id', sa.String(length=255), nullable=True),
        sa.Column('deallocated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['quark_networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subnet_id'], ['quark_subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('subnet_id', 'address', name='subnet_id_address'),
        mysql_engine='InnoDB')
    op.create_index(
        op.f('ix_quark_ip_addresses_address'),
        'quark_ip_addresses',
        ['address'],
        unique=False)
    op.create_index(
        op.f('ix_quark_ip_addresses_deallocated_at'),
        'quark_ip_addresses',
        ['deallocated_at'],
        unique=False)
    op.create_index(
        op.f('ix_quark_ip_addresses_version'),
        'quark_ip_addresses',
        ['version'],
        unique=False)
    op.create_table(
        'quark_dns_nameservers',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('ip', INET(), nullable=True),
        sa.Column('subnet_id', sa.String(length=36), nullable=True),
        sa.Column('tag_association_uuid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['subnet_id'], ['quark_subnets.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tag_association_uuid'],
                                [u'quark_tag_associations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_port_ip_address_associations',
        sa.Column('port_id', sa.String(length=36), nullable=True),
        sa.Column('ip_address_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['ip_address_id'], ['quark_ip_addresses.id'],),
        sa.ForeignKeyConstraint(['port_id'], ['quark_ports.id'], ),
        mysql_engine='InnoDB')
    op.create_table(
        'quark_nvp_driver_qos',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('display_name', sa.String(length=255), nullable=False),
        sa.Column('max_bandwidth_rate', sa.Integer(), nullable=False),
        sa.Column('min_bandwidth_rate', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_table(
        'quotas',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('resource', sa.String(length=255), nullable=True),
        sa.Column('limit', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_index(
        op.f('ix_quotas_tenant_id'),
        'quotas',
        ['tenant_id'],
        unique=False)
    op.create_table(
        'quark_nvp_driver_lswitch',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('nvp_id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=True),
        sa.Column('port_count', sa.Integer(), nullable=True),
        sa.Column('transport_zone', sa.String(length=36), nullable=True),
        sa.Column('transport_connector', sa.String(length=20), nullable=True),
        sa.Column('segment_id', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_index(
        op.f('ix_quark_nvp_driver_lswitch_network_id'),
        'quark_nvp_driver_lswitch',
        ['network_id'],
        unique=False)
    op.create_index(
        op.f('ix_quark_nvp_driver_lswitch_nvp_id'),
        'quark_nvp_driver_lswitch',
        ['nvp_id'],
        unique=False)
    op.create_table(
        'quark_nvp_driver_security_profile',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('nvp_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_index(
        op.f('ix_quark_nvp_driver_security_profile_nvp_id'),
        'quark_nvp_driver_security_profile',
        ['nvp_id'],
        unique=False)
    op.create_table(
        'quark_nvp_driver_lswitchport',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('switch_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['switch_id'],
                                ['quark_nvp_driver_lswitch.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_index(
        op.f('ix_quark_nvp_driver_lswitchport_port_id'),
        'quark_nvp_driver_lswitchport',
        ['port_id'],
        unique=False)


def downgrade():
    op.drop_table('quark_port_ip_address_associations')
    op.drop_table('quark_dns_nameservers')
    op.drop_index(op.f('ix_quark_ip_addresses_version'),
                  table_name='quark_ip_addresses')
    op.drop_index(op.f('ix_quark_ip_addresses_deallocated_at'),
                  table_name='quark_ip_addresses')
    op.drop_index(op.f('ix_quark_ip_addresses_address'),
                  table_name='quark_ip_addresses')
    op.drop_table('quark_ip_addresses')
    op.drop_table('quark_port_security_group_associations')
    op.drop_table('quark_routes')
    op.drop_index(op.f('ix_quark_subnets_tenant_id'),
                  table_name='quark_subnets')
    op.drop_index(op.f('ix_quark_subnets_segment_id'),
                  table_name='quark_subnets')
    op.drop_table('quark_subnets')
    op.drop_index(op.f('ix_quark_ports_name'), table_name='quark_ports')
    op.drop_index(op.f('ix_quark_ports_device_id'), table_name='quark_ports')
    op.drop_index('idx_ports_3', table_name='quark_ports')
    op.drop_index('idx_ports_2', table_name='quark_ports')
    op.drop_index('idx_ports_1', table_name='quark_ports')
    op.drop_table('quark_ports')
    op.drop_index(op.f('ix_quark_networks_tenant_id'),
                  table_name='quark_networks')
    op.drop_table('quark_networks')
    op.drop_table('quark_ip_policy_cidrs')
    op.drop_index(op.f('ix_quark_mac_addresses_deallocated_at'),
                  table_name='quark_mac_addresses')
    op.drop_table('quark_mac_addresses')
    op.drop_table('quark_security_group_rule')
    op.drop_table('quark_tags')
    op.drop_index(op.f('ix_quark_security_groups_tenant_id'),
                  table_name='quark_security_groups')
    op.drop_table('quark_security_groups')
    op.drop_table('quark_ip_policy')
    op.drop_table('quark_tag_associations')
    op.drop_table('quark_mac_address_ranges')
    op.drop_index(op.f('ix_quark_nvp_driver_lswitchport_port_id'),
                  table_name='quark_nvp_driver_lswitchport')
    op.drop_table('quark_nvp_driver_lswitchport')
    op.drop_index(op.f('ix_quark_nvp_driver_security_profile_nvp_id'),
                  table_name='quark_nvp_driver_security_profile')
    op.drop_table('quark_nvp_driver_security_profile')
    op.drop_index(op.f('ix_quark_nvp_driver_lswitch_nvp_id'),
                  table_name='quark_nvp_driver_lswitch')
    op.drop_index(op.f('ix_quark_nvp_driver_lswitch_network_id'),
                  table_name='quark_nvp_driver_lswitch')
    op.drop_table('quark_nvp_driver_lswitch')
    op.drop_index(op.f('ix_quotas_tenant_id'), table_name='quotas')
    op.drop_table('quotas')
    op.drop_table('quark_nvp_driver_qos')
