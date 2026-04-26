"""add scans.bom_cyclonedx + findings.cve_id columns (ADR-009 / §3.6).

Two columns added in a single migration since both belong to the OSV
SBOM run:
- `scans.bom_cyclonedx` — JSONB; persists the CycloneDX SBOM emitted
  by OSV-Scanner during the deterministic pre-pass. Hard-capped at
  5 MB by `osv_runner`. Nullable for legacy scans + OSV-unavailable
  scans.
- `findings.cve_id` — String(64); CVE identifier for OSV findings
  (e.g. `CVE-2024-12345`). Indexed for `?source=osv&cve_id=...` admin
  filter. Nullable; only OSV findings populate it.

Revision ID: 62279996f0bc
Revises: 58e63627dc6b
Create Date: 2026-04-26 16:11:33.325942
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "62279996f0bc"
down_revision: Union[str, None] = "58e63627dc6b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "bom_cyclonedx",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.add_column(
        "findings",
        sa.Column("cve_id", sa.String(length=64), nullable=True),
    )
    op.create_index(
        op.f("ix_findings_cve_id"),
        "findings",
        ["cve_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_cve_id"), table_name="findings")
    op.drop_column("findings", "cve_id")
    op.drop_column("scans", "bom_cyclonedx")
