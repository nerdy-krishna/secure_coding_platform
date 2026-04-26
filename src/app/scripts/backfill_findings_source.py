"""Backfill ``findings.source = 'agent'`` for legacy LLM-emitted rows.

Pre-prescan findings (everything before the SAST pre-pass shipped) have
``source IS NULL``. The dashboard's per-source counter (Group D2) and
the admin findings list filter (Group D1) need a non-null bucket for
those rows. ``"agent"`` is the natural label that distinguishes them
from new scanner-emitted rows (``"bandit"`` / ``"semgrep"`` /
``"gitleaks"``).

Idempotent: re-running on a fully-backfilled DB returns 0 updated
and exits cleanly.

Usage:

    docker compose exec app python -m app.scripts.backfill_findings_source --dry-run
    docker compose exec app python -m app.scripts.backfill_findings_source

Per N10 (sast-prescan-followups threat model):
- Lives under ``app/scripts/``, never imported by any router or MCP
  tool (CI grep-check enforces).
- Batched ``UPDATE ... LIMIT 1000`` with inter-batch sleep so
  ``AccessExclusiveLock`` is not held for long on a million-row
  ``findings`` table.
- ``--dry-run`` reports candidate count without writing.
- Logs per-batch progress so operators can watch + abort.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Optional

from sqlalchemy import text

from app.infrastructure.database import AsyncSessionLocal


logger = logging.getLogger("app.scripts.backfill_findings_source")


async def _count_candidates(session) -> int:
    result = await session.execute(
        text("SELECT count(*) FROM findings WHERE source IS NULL")
    )
    return int(result.scalar() or 0)


async def _update_one_batch(session, batch_size: int) -> int:
    """Update up to ``batch_size`` candidate rows; returns row count."""
    result = await session.execute(
        text(
            """
            UPDATE findings
            SET source = 'agent'
            WHERE id IN (
                SELECT id FROM findings
                WHERE source IS NULL
                ORDER BY id
                LIMIT :batch_size
            )
            RETURNING id
            """
        ),
        {"batch_size": batch_size},
    )
    return len(result.all())


async def backfill(
    *, dry_run: bool, batch_size: int, sleep_ms: int, max_batches: Optional[int] = None
) -> int:
    """Run the backfill loop. Returns total rows updated (0 on dry-run)."""
    async with AsyncSessionLocal() as session:
        candidates = await _count_candidates(session)
        logger.info(
            "backfill_findings_source: dry_run=%s batch_size=%d sleep_ms=%d candidates=%d",
            dry_run,
            batch_size,
            sleep_ms,
            candidates,
        )
        if dry_run:
            return 0
        if candidates == 0:
            return 0

        total_updated = 0
        batch_no = 0
        while True:
            batch_no += 1
            updated = await _update_one_batch(session, batch_size)
            await session.commit()
            total_updated += updated
            logger.info(
                "backfill_findings_source: batch=%d updated=%d total_updated=%d",
                batch_no,
                updated,
                total_updated,
            )
            if updated == 0:
                break
            if max_batches is not None and batch_no >= max_batches:
                logger.info(
                    "backfill_findings_source: reached --max-batches=%d; "
                    "stopping with %d remaining (re-run to continue)",
                    max_batches,
                    candidates - total_updated,
                )
                break
            if sleep_ms > 0:
                await asyncio.sleep(sleep_ms / 1000.0)

        logger.info(
            "backfill_findings_source: COMPLETE total_updated=%d batches=%d",
            total_updated,
            batch_no,
        )
        return total_updated


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Backfill findings.source='agent' for legacy LLM-emitted rows."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report candidate count, do not write.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Rows per UPDATE batch (default 1000).",
    )
    parser.add_argument(
        "--sleep-ms",
        type=int,
        default=50,
        help="Sleep between batches in milliseconds (default 50).",
    )
    parser.add_argument(
        "--max-batches",
        type=int,
        default=None,
        help="Stop after this many batches (default: until done).",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    total = asyncio.run(
        backfill(
            dry_run=args.dry_run,
            batch_size=args.batch_size,
            sleep_ms=args.sleep_ms,
            max_batches=args.max_batches,
        )
    )
    logger.info("Final total_updated=%d (dry_run=%s)", total, args.dry_run)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
