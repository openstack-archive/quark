"""Create enabled and do_not_use columns

Revision ID: 5927940a466e
Revises: 552b213c2b8c
Create Date: 2014-07-07 07:50:39.372294

"""

# revision identifiers, used by Alembic.
revision = '5927940a466e'
down_revision = '552b213c2b8c'

from alembic import op
import sqlalchemy as sa

#
# SQLite has features that it does not implement fully.
# E.g., ALTER TABLE support is not fully implemented.
# For more info see here: http://www.sqlite.org/omitted.html
#
# To work around op.add_column and op.drop_column warnings,
# we need to use the batch operations.
# See batch_alter_table at
# http://alembic.zzzcomputing.com/en/latest/ops.html
#

t1_name = 'quark_port_ip_address_associations'
t2_name = 'quark_mac_address_ranges'

def upgrade():
    with op.batch_alter_table(t1_name) as batch_op:
        batch_op.add_column(sa.Column('enabled',
                                      sa.Boolean(),
                                      nullable=False,
                                      server_default='1'))

    with op.batch_alter_table(t2_name) as batch_op:
        batch_op.add_column(sa.Column('do_not_use',
                                      sa.Boolean(),
                                      nullable=False,
                                      server_default='0'))

def downgrade():
    """alexm: i believe this method is never called"""
    with op.batch_alter_table(t2_name) as batch_op:
        batch_op.drop_column('do_not_use')

    with op.batch_alter_table(t1_name) as batch_op:
        batch_op.drop_column('enabled')
