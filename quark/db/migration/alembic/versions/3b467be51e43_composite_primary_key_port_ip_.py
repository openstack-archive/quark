"""composite primary key port ip association

Revision ID: 3b467be51e43
Revises: 26e984b48a0d
Create Date: 2014-10-09 15:42:58.104964

"""

# revision identifiers, used by Alembic.
revision = '3b467be51e43'
down_revision = '26e984b48a0d'

import contextlib
import itertools

from alembic import op
import sqlalchemy as sa


def _drop_foreign_key(op, table, fk):
    op.drop_constraint(fk.name, table.name, type_="foreignkey")


def _create_foreign_key(op, table, fk):
    ref_tbl_name = fk.column.table.name
    ref_tbl_col = fk.column.name
    op.create_foreign_key(fk.name, table.name, ref_tbl_name,
                          [fk.parent.name], [ref_tbl_col])


def _alter_foreign_keys(op, table, action, fk_constraints):
    actions = {
        "drop": _drop_foreign_key,
        "create": _create_foreign_key
    }
    # NOTE(thomasem): Flatten list of ForeignKeys we want to work on from the
    # ForeignKeyConstraint objects that may contain multiple ForeignKey
    # objects.
    [actions[action](op, table, fk) for fk
     in itertools.chain.from_iterable([c.elements for c in fk_constraints])]


@contextlib.contextmanager
def _foreign_keys_dropped(op, table):
    fk_constraints = [c for c in table.constraints
                      if isinstance(c, sa.schema.ForeignKeyConstraint)]
    _alter_foreign_keys(op, table, "drop", fk_constraints)
    yield
    _alter_foreign_keys(op, table, "create", fk_constraints)


def upgrade():
    metadata = sa.MetaData(bind=op.get_bind())
    table = sa.Table('quark_port_ip_address_associations', metadata,
                     autoload=True)
    with _foreign_keys_dropped(op, table):
        op.alter_column('quark_port_ip_address_associations', 'ip_address_id',
                        existing_type=sa.String(36), nullable=False)
        op.alter_column('quark_port_ip_address_associations', 'port_id',
                        existing_type=sa.String(36), nullable=False)
        op.create_primary_key("pk_quark_port_ip_address_associations",
                              "quark_port_ip_address_associations",
                              ['port_id', 'ip_address_id'])


def downgrade():
    metadata = sa.MetaData(bind=op.get_bind())
    table = sa.Table('quark_port_ip_address_associations', metadata,
                     autoload=True)
    # NOTE(thomasem): Unfortunately we cannot remove primary keys for columns
    # that have a ForeignKeyConstraint defined. So, we can temporarily remove
    # them and add them back as soon as the PrimaryKeyConstraint is removed.
    with _foreign_keys_dropped(op, table):
        op.drop_constraint("pk_quark_port_ip_address_associations",
                           "quark_port_ip_address_associations",
                           type_="primary")
        op.alter_column('quark_port_ip_address_associations', 'port_id',
                        existing_type=sa.String(36), nullable=True)
        op.alter_column('quark_port_ip_address_associations', 'ip_address_id',
                        existing_type=sa.String(36), nullable=True)
