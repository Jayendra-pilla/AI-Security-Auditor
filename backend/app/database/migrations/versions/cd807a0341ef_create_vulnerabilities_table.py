"""create vulnerabilities table

Revision ID: cd807a0341ef
Revises: f66500b955f7
Create Date: 2026-07-04 20:26:56.605358

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cd807a0341ef'
down_revision: Union[str, Sequence[str], None] = 'f66500b955f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('scanner_name', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=False),
        sa.Column('recommendation', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vulnerabilities_id'), 'vulnerabilities', ['id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_scan_id'), 'vulnerabilities', ['scan_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_vulnerabilities_scan_id'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_id'), table_name='vulnerabilities')
    op.drop_table('vulnerabilities')
