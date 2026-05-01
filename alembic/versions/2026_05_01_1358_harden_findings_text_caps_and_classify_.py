"""harden findings text caps and classify sensitive fields

Revision ID: 678449efd5c1
Revises: c0f39ef37367
Create Date: 2026-05-01 13:58:11.122438

V02.2.1 — bound `findings.title` (Text → VARCHAR(512)) and add
CheckConstraints capping `findings.description` / `findings.remediation`
at 65,535 characters. Defence-in-depth against attacker-controlled
agent output bloating row size.

V15.3.1 — `info={"sensitive": True}` on `LLMConfiguration.encrypted_api_key`
is mapper-level metadata only (no DDL impact).

Note: Autogenerate flagged spurious drops on `ix_scan_outbox_unpublished`
and `ix_user_group_memberships_user_id` due to partial-index introspection
quirks; those operations are intentionally NOT in this migration.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "678449efd5c1"
down_revision: Union[str, None] = "c0f39ef37367"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # V02.2.1: cap finding title at 512 chars at the persistence layer.
    op.alter_column(
        "findings",
        "title",
        existing_type=sa.TEXT(),
        type_=sa.String(length=512),
        existing_nullable=False,
    )
    # V02.2.1: cap description and remediation at 65,535 chars via DB-level
    # CheckConstraints (the columns stay TEXT to avoid a destructive type
    # change on existing rows but the constraint enforces the upper bound
    # going forward).
    op.create_check_constraint(
        "ck_findings_description_maxlen",
        "findings",
        "length(description) <= 65535",
    )
    op.create_check_constraint(
        "ck_findings_remediation_maxlen",
        "findings",
        "length(remediation) <= 65535",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "ck_findings_remediation_maxlen",
        "findings",
        type_="check",
    )
    op.drop_constraint(
        "ck_findings_description_maxlen",
        "findings",
        type_="check",
    )
    op.alter_column(
        "findings",
        "title",
        existing_type=sa.String(length=512),
        type_=sa.TEXT(),
        existing_nullable=False,
    )
