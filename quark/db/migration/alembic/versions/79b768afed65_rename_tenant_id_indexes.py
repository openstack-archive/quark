"""rename tenant id indexes

Revision ID: 79b768afed65
Revises: 271cce54e15b
Create Date: 2015-05-20 21:39:19.348638

"""

# revision identifiers, used by Alembic.
revision = '79b768afed65'
down_revision = '271cce54e15b'

from alembic import op
import sqlalchemy as sa

from neutron.api.v2 import attributes as attr


_INSPECTOR = None


def get_inspector():
    """Reuse inspector"""

    global _INSPECTOR

    if _INSPECTOR:
        return _INSPECTOR

    else:
        bind = op.get_bind()
        _INSPECTOR = sa.engine.reflection.Inspector.from_engine(bind)

    return _INSPECTOR


def get_tables():

    tables = [
        'quark_tags',
        'quark_routes',
        'quark_dns_nameservers',
        'quark_security_group_rules',
        'quark_security_groups',
        'quark_ports',
        'quark_mac_addresses',
        'quark_ip_policy',
        'quark_subnets',
        'quark_networks',
        'quark_async_transactions',
        'quotas',
        'address_scopes',
        'floatingips',
        'meteringlabels',
        'networkrbacs',
        'networks',
        'ports',
        'qos_policies',
        'qospolicyrbacs',
        'reservations',
        'routers',
        'securitygrouprules',
        'securitygroups',
        'subnetpools',
        'subnets',
        'trunks',
        'auto_allocated_topologies',
        'default_security_group',
        'ha_router_networks',
        'quotausages',
        'vips',
        'members',
        'pools',
        'healthmonitors',
        'lbaas_members',
        'lbaas_healthmonitors',
        'lbaas_loadbalancers',
        'lbaas_pools',
        'lbaas_l7rules',
        'lbaas_l7policies',
        'lbaas_listeners',
    ]

    return tables


def get_columns(table):
    """Returns list of columns for given table."""
    inspector = get_inspector()
    return inspector.get_columns(table)


def get_data():
    """Returns combined list of tuples: [(table, column)].

    List is built, based on retrieved tables, where column with name
    ``tenant_id`` exists.
    """

    output = []
    tables = get_tables()
    for table in tables:
        try:
            columns = get_columns(table)
        except sa.exc.NoSuchTableError:
            continue

        for column in columns:
            if column['name'] == 'tenant_id':
                output.append((table, column))

    return output


def alter_column(table, column):
    old_name = 'tenant_id'
    new_name = 'project_id'

    coltype = sa.String(attr.TENANT_ID_MAX_LEN)

    op.alter_column(
        table_name=table,
        column_name=old_name,
        new_column_name=new_name,
        type_=coltype,
        existing_nullable=column['nullable']
    )


def recreate_index(index, table_name):
    old_name = index['name']
    new_name = old_name.replace('tenant', 'project')

    op.drop_index(op.f(old_name), table_name)
    op.create_index(new_name, table_name, ['project_id'])


def upgrade():
    data = get_data()

    for table, column in data:
        alter_column(table, column)

    op.drop_index(op.f('ix_quark_networks_tenant_id'),
                  table_name='quark_networks')
    op.drop_index(op.f('ix_quark_networks_tenant_id_name'),
                  table_name='quark_networks')

    op.drop_index(op.f('ix_quark_subnets_tenant_id'),
                  table_name='quark_subnets')
    op.drop_index(op.f('ix_quark_subnets_network_id_tenant_id'),
                  table_name='quark_subnets')

    op.drop_index(op.f('ix_quark_ports_tenant_id'),
                  table_name='quark_ports')
    op.drop_index(op.f('ix_quark_ports_network_id_tenant_id'),
                  table_name='quark_ports')
    op.drop_index(op.f('ix_quark_ports_name_tenant_id'),
                  table_name='quark_ports')
    op.drop_index(op.f('ix_quotas_tenant_id'),
                  table_name='quotas')

    op.create_index(op.f('ix_quark_networks_project_id'),
                    'quark_networks',
                    ['project_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_networks_project_id_name'),
                    'quark_networks',
                    ['project_id', 'name'],
                    unique=False)
    op.create_index(op.f('ix_quark_subnets_project_id'),
                    'quark_subnets',
                    ['project_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_subnets_network_id_project_id'),
                    'quark_subnets',
                    ['network_id', 'project_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_ports_project_id'),
                    'quark_ports',
                    ['project_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_ports_network_id_project_id'),
                    'quark_ports',
                    ['network_id', 'project_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_ports_name_project_id'),
                    'quark_ports',
                    ['name', 'project_id'],
                    unique=False)
    op.create_index(op.f('ix_quotas_project_id'),
                    'quotas',
                    ['project_id'],
                    unique=False)


def downgrade():
    op.drop_index(op.f('ix_quark_networks_project_id'),
                  table_name='quark_networks')
    op.drop_index(op.f('ix_quark_networks_project_id_name'),
                  table_name='quark_networks')
    op.drop_index(op.f('ix_quark_subnets_project_id'),
                  table_name='quark_subnets')
    op.drop_index(op.f('ix_quark_subnets_network_id_project_id'),
                  table_name='quark_subnets')
    op.drop_index(op.f('ix_quark_ports_project_id'),
                  table_name='ports')
    op.drop_index(op.f('ix_quark_ports_network_id_project_id'),
                  table_name='quark_ports')
    op.drop_index(op.f('ix_quark_ports_name_project_id'),
                  table_name='quark_ports')
    op.drop_index(op.f('ix_quotas_project_id'),
                  table_name='quotas')
