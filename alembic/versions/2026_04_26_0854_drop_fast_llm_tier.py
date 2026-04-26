"""drop fast_llm_tier

Drops the unused `scans.fast_llm_config_id` column + FK. The Fast LLM
tier was reserved for future optimization (triage / dep summarization)
but never wired up — the column carried only NULLs or unused
defaults. Downgrade restores the column as nullable + FK to
`llm_configurations.id`; **historical values are NOT preserved**
(they were not meaningful in the first place).

Worker checkpointer compatibility: in-flight scans paused at
`estimate_cost_node`'s `interrupt()` may have `fast_llm_config_id`
in their serialized `WorkerState` dict. `WorkerState` is a TypedDict
(no runtime key validation), so resume after this migration is safe
— the extra key is silently retained but never read by the
post-migration code.

Revision ID: 58e63627dc6b
Revises: 72a74f13d062
Create Date: 2026-04-26 08:54:30.618290

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "58e63627dc6b"
down_revision: Union[str, None] = "72a74f13d062"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop the FK first, then the column."""
    op.drop_constraint(
        op.f("fk_scans_fast_llm_config_id_llm_configurations"),
        "scans",
        type_="foreignkey",
    )
    op.drop_column("scans", "fast_llm_config_id")


def downgrade() -> None:
    """Restore the column as nullable + FK to llm_configurations.id."""
    op.add_column(
        "scans",
        sa.Column("fast_llm_config_id", sa.UUID(), autoincrement=False, nullable=True),
    )
    op.create_foreign_key(
        op.f("fk_scans_fast_llm_config_id_llm_configurations"),
        "scans",
        "llm_configurations",
        ["fast_llm_config_id"],
        ["id"],
    )
