"""FAWS: Added fields for SG migration

Revision ID: c07cd8303997
Revises: da46a8b30bd8
Create Date: 2016-09-14 15:51:53.112929

"""

# revision identifiers, used by Alembic.
revision = 'c07cd8303997'
down_revision = 'da46a8b30bd8'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('quark_security_groups', sa.Column('external_service',
                                                     sa.String(255)))
    op.add_column('quark_security_groups', sa.Column('external_service_id',
                                                     sa.String(255)))
    op.add_column('quark_security_group_rules', sa.Column('external_service',
                                                     sa.String(255)))
    op.add_column('quark_security_group_rules', sa.Column('external_service_id',
                                                     sa.String(255)))


def downgrade():
    op.drop_column('quark_security_groups', 'external_service')
    op.drop_column('quark_security_groups', 'external_service_id')
    op.drop_column('quark_security_group_rules', 'external_service')
    op.drop_column('quark_security_group_rules', 'external_service_id')
