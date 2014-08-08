"""create lswitch and lswitch port orphaned tables

Revision ID: 1284c81cf727
Revises: 4358d1b8cc75
Create Date: 2014-07-02 23:05:20.855269

"""

# revision identifiers, used by Alembic.
revision = '1284c81cf727'
down_revision = '4358d1b8cc75'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'quark_nvp_orphaned_lswitches',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('nvp_id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_index(
        'ix_quark_nvp_orphaned_lswitches_nvp_id',
        'quark_nvp_orphaned_lswitches',
        ['nvp_id'],
        unique=False)
    op.create_index(
        'ix_quark_nvp_orphaned_lswitches_network_id',
        'quark_nvp_orphaned_lswitches',
        ['network_id'],
        unique=False)
    op.create_index(
        'ix_quark_nvp_orphaned_lswitches_display_name',
        'quark_nvp_orphaned_lswitches',
        ['display_name'],
        unique=False)
    op.create_table(
        'quark_nvp_orphaned_lswitch_ports',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB')
    op.create_index(
        'ix_quark_nvp_orphaned_lswitch_ports_port_id',
        'quark_nvp_orphaned_lswitch_ports',
        ['port_id'],
        unique=False)


def downgrade():
    op.drop_index('ix_quark_nvp_orphaned_lswitches_nvp_id')
    op.drop_index('ix_quark_nvp_orphaned_lswitches_network_id')
    op.drop_index('ix_quark_nvp_orphaned_lswitches_display_name')
    op.drop_table('quark_nvp_orphaned_lswitches')
    op.drop_index('ix_quark_nvp_orphaned_lswitch_ports_port_id')
    op.drop_table('quark_nvp_orphaned_lswitch_ports')
