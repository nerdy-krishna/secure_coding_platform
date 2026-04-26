"""partial findings.source index where not null

Swap the existing full ``ix_findings_source`` index for a partial
index ``WHERE source IS NOT NULL``. Pre-prescan rows have
``source = NULL``; a non-partial index pays write-amplification on
the long NULL-only legacy tail without ever being used by the planner
to filter.

Revision ID: 72a74f13d062
Revises: c592cea478fe
Create Date: 2026-04-26 07:06:08.385340

"""

from typing import Sequence, Union

from alembic import op
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = "72a74f13d062"
down_revision: Union[str, None] = "c592cea478fe"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop the full index, recreate as a partial index."""
    op.drop_index("ix_findings_source", table_name="findings")
    op.create_index(
        "ix_findings_source",
        "findings",
        ["source"],
        unique=False,
        postgresql_where=text("source IS NOT NULL"),
    )


def downgrade() -> None:
    """Reverse: drop the partial index, recreate the full index."""
    op.drop_index("ix_findings_source", table_name="findings")
    op.create_index(
        "ix_findings_source",
        "findings",
        ["source"],
        unique=False,
    )
