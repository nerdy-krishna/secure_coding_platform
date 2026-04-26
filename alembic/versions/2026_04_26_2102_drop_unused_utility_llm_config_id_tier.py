"""drop unused utility_llm_config_id tier

The utility tier was reserved alongside the now-deleted fast tier
(commit 7a58714) for cheap orchestration LLM calls, but every code
path uses `reasoning_llm_config_id` exclusively. The
`analyze_files_parallel_node` validates the column is present then
hardcodes the per-agent state's `llm_config_id` to the reasoning
slot. With this migration only `reasoning_llm_config_id` remains.

Reversible downgrade restores the column as nullable + FK to
`llm_configurations.id`. Historical values are NOT preserved
(acceptable; column was never user-meaningful, mirrors fast-tier
removal policy).

Revision ID: 6b06a5036276
Revises: c00c968f0503
Create Date: 2026-04-26 21:02:40.061678

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "6b06a5036276"
down_revision: Union[str, None] = "c00c968f0503"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_constraint(
        op.f("fk_scans_utility_llm_config_id_llm_configurations"),
        "scans",
        type_="foreignkey",
    )
    op.drop_column("scans", "utility_llm_config_id")


def downgrade() -> None:
    """Downgrade schema."""
    op.add_column(
        "scans",
        sa.Column(
            "utility_llm_config_id", sa.UUID(), autoincrement=False, nullable=True
        ),
    )
    op.create_foreign_key(
        op.f("fk_scans_utility_llm_config_id_llm_configurations"),
        "scans",
        "llm_configurations",
        ["utility_llm_config_id"],
        ["id"],
    )
