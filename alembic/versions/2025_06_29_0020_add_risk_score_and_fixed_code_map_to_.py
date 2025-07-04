"""Add risk_score and fixed_code_map to submissions

Revision ID: 68d9b6d5d8a6
Revises: 4da496ea0231
Create Date: 2025-06-29 00:20:09.048394

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "68d9b6d5d8a6"
down_revision: Union[str, None] = "4da496ea0231"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column(
        "code_submissions",
        sa.Column(
            "risk_score",
            sa.Integer(),
            nullable=True,
            comment="Calculated risk score based on finding severity.",
        ),
    )
    op.add_column(
        "code_submissions",
        sa.Column(
            "fixed_code_map",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Stores the file content after remediation.",
        ),
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("code_submissions", "fixed_code_map")
    op.drop_column("code_submissions", "risk_score")
    # ### end Alembic commands ###
