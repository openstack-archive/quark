"""add scaling ip address type enum

Revision ID: 3f0c11478a5d
Revises: a0798b3b7418
Create Date: 2016-01-22 23:41:03.214930

"""

# revision identifiers, used by Alembic.
revision = '3f0c11478a5d'
down_revision = 'a0798b3b7418'

from alembic import op
import sqlalchemy as sa


existing_enum = sa.Enum("shared", "floating", "fixed")
new_enum = sa.Enum("shared", "floating", "fixed", "scaling")


def upgrade():
    op.alter_column("quark_ip_addresses", "address_type",
                    existing_type=existing_enum,
                    type_=new_enum)


def downgrade():
    op.alter_column("quark_ip_addresses", "address_type",
                    existing_type=new_enum,
                    type_=existing_enum)
