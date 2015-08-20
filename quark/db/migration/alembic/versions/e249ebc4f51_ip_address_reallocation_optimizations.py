"""IP Address reallocation optimizations

Revision ID: e249ebc4f51
Revises: 5932938bb839
Create Date: 2015-08-20 01:08:04.554914

"""

# revision identifiers, used by Alembic.
revision = 'e249ebc4f51'
down_revision = '5932938bb839'

from alembic import op


def upgrade():
    op.create_index(op.f('ix_quark_reallocate_ip_addresses_network'),
                    'quark_ip_addresses',
                    ["network_id", "deallocated_at", "version",
                     "_deallocated"],
                    unique=False)
    op.create_index(op.f('ix_quark_reallocate_ip_addresses_subnet'),
                    'quark_ip_addresses',
                    ["deallocated_at", "subnet_id", "_deallocated"],
                    unique=False)


def downgrade():
    # These will never be run, upstream has disabled rollbacks
    op.drop_index(op.f('ix_quark_reallocate_ip_addresses_network'),
                  table_name='quark_ip_addresses')
    op.drop_index(op.f('ix_quark_reallocate_ip_addresses_subnet'),
                  table_name='quark_ip_addresses')
