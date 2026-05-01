"""add raw_content_retention_consent to rag jobs

Revision ID: f888d36f2dc5
Revises: 8d3029fce81f
Create Date: 2026-05-01 14:29:44.531569

V14.2.8 — adds an explicit consent flag for storing raw upload bytes
on RAG preprocessing jobs. Defaults to false so existing rows remain
treated as "not consented" (their `raw_content` may still be set if
previously written; the consent flag governs *new* writes).

Server default = "false" so the column is fail-closed on insert.

Note: autogenerate flagged spurious drops on `ix_scan_outbox_unpublished`
and `ix_user_group_memberships_user_id` due to partial-index
introspection quirks; those operations are intentionally NOT in this
migration.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f888d36f2dc5"
down_revision: Union[str, None] = "8d3029fce81f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "rag_preprocessing_jobs",
        sa.Column(
            "raw_content_retention_consent",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("rag_preprocessing_jobs", "raw_content_retention_consent")
