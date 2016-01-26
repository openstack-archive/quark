"""add_segment_allocations

Revision ID: 1bd7cff90384
Revises: 374c1bdb4480
Create Date: 2016-01-25 19:26:27.899610

"""

# revision identifiers, used by Alembic.
revision = '1bd7cff90384'
down_revision = '374c1bdb4480'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'quark_segment_allocation_ranges',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('segment_id', sa.String(length=36), nullable=True),
        sa.Column('segment_type', sa.String(length=36), nullable=True),
        sa.Column('first_id', sa.BigInteger(), nullable=False),
        sa.Column('last_id', sa.BigInteger(), nullable=False),
        sa.Column('do_not_use', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB'
    )
    op.create_index(op.f('ix_quark_segment_allocation_ranges_segment_id'),
                    'quark_segment_allocation_ranges', ['segment_id'],
                    unique=False)
    op.create_index(op.f('ix_quark_segment_allocation_ranges_segment_type'),
                    'quark_segment_allocation_ranges', ['segment_type'],
                    unique=False)
    op.create_table(
        'quark_segment_allocations',
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('id', sa.BigInteger(), autoincrement=False,
                  nullable=False),
        sa.Column('segment_id', sa.String(length=36), nullable=False),
        sa.Column('segment_type', sa.String(length=36), nullable=False),
        sa.Column('segment_allocation_range_id', sa.String(length=36),
                  nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('deallocated', sa.Boolean(), nullable=True),
        sa.Column('deallocated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['segment_allocation_range_id'],
                                ['quark_segment_allocation_ranges.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', 'segment_id', 'segment_type'),
        mysql_engine='InnoDB'
    )
    op.create_index(op.f('ix_quark_segment_allocations_deallocated'),
                    'quark_segment_allocations', ['deallocated'],
                    unique=False)
    op.create_index(op.f('ix_quark_segment_allocations_deallocated_at'),
                    'quark_segment_allocations', ['deallocated_at'],
                    unique=False)


def downgrade():
    op.drop_index(op.f('ix_quark_segment_allocations_deallocated_at'),
                  table_name='quark_segment_allocations')
    op.drop_index(op.f('ix_quark_segment_allocations_deallocated'),
                  table_name='quark_segment_allocations')
    op.drop_table('quark_segment_allocations')
    op.drop_index(op.f('ix_quark_segment_allocation_ranges_segment_type'),
                  table_name='quark_segment_allocation_ranges')
    op.drop_index(op.f('ix_quark_segment_allocation_ranges_segment_id'),
                  table_name='quark_segment_allocation_ranges')
    op.drop_table('quark_segment_allocation_ranges')
