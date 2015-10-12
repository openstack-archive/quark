"""add_tags_to_port

Revision ID: 4da4444d7706
Revises: 2e9cf60b0ef6
Create Date: 2015-10-12 16:46:14.116338

"""

# revision identifiers, used by Alembic.
revision = '4da4444d7706'
down_revision = '2e9cf60b0ef6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('quark_ports',
                  sa.Column('tag_association_uuid',
                            sa.String(length=36), nullable=True))


def downgrade():
    op.drop_column('quark_ports', 'tag_association_uuid')
