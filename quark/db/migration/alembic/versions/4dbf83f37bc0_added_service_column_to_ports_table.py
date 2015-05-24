"""Added service column to port table

Revision ID: 4dbf83f37bc0
Revises: 33e9e23ba761
Create Date: 2015-05-26 13:27:38.995202

"""

# revision identifiers, used by Alembic.
revision = '4dbf83f37bc0'
down_revision = '1bdc1b574beb'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('quark_ports', sa.Column('service', sa.String(length=255),
                                           nullable=False,
                                           server_default="none"))


def downgrade():
    op.drop_column('quark_ports', 'service')
