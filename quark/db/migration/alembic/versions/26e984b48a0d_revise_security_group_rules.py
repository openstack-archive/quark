"""Revise security group rules

Revision ID: 26e984b48a0d
Revises: 1664300cb03a
Create Date: 2014-09-16 22:01:07.329380

"""

# revision identifiers, used by Alembic.
revision = '26e984b48a0d'
down_revision = '1664300cb03a'

from alembic import op
import sqlalchemy as sa


OLD_TABLE = "quark_security_group_rule"
NEW_TABLE = "quark_security_group_rules"


def upgrade():
    # NOTE(mdietz): You can't change the datatype or remove columns,
    #               in SQLite, please see
    #               http://sqlite.org/lang_altertable.html
    op.drop_table(OLD_TABLE)
    op.create_table(
        NEW_TABLE,
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('group_id', sa.String(length=36), nullable=False),
        sa.Column('direction', sa.String(length=10), nullable=False),
        sa.Column('port_range_max', sa.Integer(), nullable=True),
        sa.Column('port_range_min', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.Integer(), nullable=True),
        sa.Column("ethertype", type_=sa.Integer(), nullable=False),
        sa.Column('remote_group_id', sa.String(length=36), nullable=True),
        sa.Column("remote_ip_prefix", type_=sa.String(255)),
        sa.ForeignKeyConstraint(["remote_group_id"],
                                ["quark_security_groups.id"],
                                "fk_remote_group_id"),
        sa.ForeignKeyConstraint(['group_id'], ['quark_security_groups.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine="InnoDB")


def downgrade():
    op.drop_table(NEW_TABLE)
    op.create_table(
        OLD_TABLE,
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
