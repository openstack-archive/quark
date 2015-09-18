"""Implements reservations, resourcedeltas and quota usages from upstream

Revision ID: 2e9cf60b0ef6
Revises: 341d2e702dc4
Create Date: 2015-09-13 13:46:03.888079

"""

# revision identifiers, used by Alembic.
revision = '2e9cf60b0ef6'
down_revision = '341d2e702dc4'

from alembic import op
import sqlalchemy as sa
from sqlalchemy import sql


def upgrade():
    op.create_table(
        'reservations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('expiration', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'resourcedeltas',
        sa.Column('resource', sa.String(length=255), nullable=False),
        sa.Column('reservation_id', sa.String(length=36), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['reservation_id'], ['reservations.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('resource', 'reservation_id'))

    op.create_table(
        'quotausages',
        sa.Column('tenant_id', sa.String(length=255),
                  nullable=False, primary_key=True, index=True),
        sa.Column('resource', sa.String(length=255),
                  nullable=False, primary_key=True, index=True),
        sa.Column('dirty', sa.Boolean(), nullable=False,
                  server_default=sql.false()),
        sa.Column('in_use', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('reserved', sa.Integer(), nullable=False,
                  server_default='0'))
