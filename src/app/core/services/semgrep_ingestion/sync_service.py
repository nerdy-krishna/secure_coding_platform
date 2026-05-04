# src/app/core/services/semgrep_ingestion/sync_service.py
import asyncio
import logging
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.repositories.semgrep_rule_repo import SemgrepRuleRepository

from .fetcher import clone_or_pull
from .parser import parse_rule_file
from .validator import validate_rule_file
from .selector import _load_ingestion_settings

logger = logging.getLogger(__name__)

# YAML file extensions to consider
_YAML_EXTS = {".yaml", ".yml"}
# File name patterns to skip (test files)
_SKIP_SUFFIXES = (".test.yaml", ".test.yml")


def _walk_rule_files(root: Path, subpath: str | None) -> list[Path]:
    scan_root = root / subpath if subpath else root
    if not scan_root.exists():
        return []
    return [
        p for p in scan_root.rglob("*")
        if p.suffix.lower() in _YAML_EXTS
        and not p.name.endswith(_SKIP_SUFFIXES)
        and p.is_file()
    ]


async def _run_sync_inner(
    source: db_models.SemgrepRuleSource,
    run: db_models.SemgrepSyncRun,
    repo: SemgrepRuleRepository,
    workdir: Path,
) -> None:
    """Core sync logic — mutates run/source counters via repo."""
    sha_before = source.last_commit_sha

    # 1. Clone / pull
    sha_after = await clone_or_pull(source, workdir)
    run.commit_sha_before = sha_before
    run.commit_sha_after = sha_after

    # 2. Walk files
    repo_dir = workdir / source.slug
    files = _walk_rule_files(repo_dir, source.subpath)
    logger.info(
        "semgrep.sync.files_found",
        extra={"source": source.slug, "count": len(files)},
    )

    rules_added = 0
    rules_updated = 0
    rules_invalid = 0
    seen_namespaced_ids: set[str] = set()

    # Process files in batches of 100 to avoid holding the session open for too long
    for path in files:
        # Validate first
        is_valid = await validate_rule_file(path)
        if not is_valid:
            rules_invalid += 1
            continue

        # Parse
        rule_dicts = parse_rule_file(path, source, repo_dir)
        for rd in rule_dicts:
            seen_namespaced_ids.add(rd["namespaced_id"])
            _, is_new = await repo.upsert_rule(source.id, rd)
            if is_new:
                rules_added += 1
            else:
                rules_updated += 1

    # 3. Remove stale rules (no longer in repo)
    rules_removed = await repo.delete_rules_not_in(source.id, seen_namespaced_ids)

    # 4. Update source stats
    total_count = rules_added + rules_updated  # current rules = surviving ones
    source.last_synced_at = datetime.now(tz=timezone.utc)
    source.last_commit_sha = sha_after
    source.last_sync_status = "success"
    source.last_sync_error = None
    source.rule_count = total_count

    # 5. Finalize run
    run.rules_added = rules_added
    run.rules_updated = rules_updated
    run.rules_removed = rules_removed
    run.rules_invalid = rules_invalid
    run.status = "success"
    run.finished_at = datetime.now(tz=timezone.utc)

    logger.info(
        "semgrep.sync.completed",
        extra={
            "source": source.slug,
            "added": rules_added,
            "updated": rules_updated,
            "removed": rules_removed,
            "invalid": rules_invalid,
        },
    )


async def run_sync(source_id: uuid.UUID, triggered_by: str) -> None:
    """
    Run a full sync for the given source. Safe to call from BackgroundTasks or the sweeper.
    All errors are captured in the DB — never re-raises.
    """
    async with AsyncSessionLocal() as db:
        async with db.begin():
            repo = SemgrepRuleRepository(db)
            source = await repo.get_source_by_id(source_id)
            if not source:
                logger.error("semgrep.sync.source_not_found", extra={"source_id": str(source_id)})
                return

            # Prevent concurrent syncs on the same source via advisory lock
            lock_key = source_id.int & 0x7FFFFFFFFFFFFFFF  # Postgres bigint range
            try:
                await db.execute(
                    __import__("sqlalchemy").text(f"SELECT pg_try_advisory_xact_lock({lock_key})")
                )
            except Exception:
                pass  # advisory locks are best-effort

            # Mark source as running
            source.last_sync_status = "running"
            run = await repo.create_sync_run(source_id=source_id, triggered_by=triggered_by)
            await db.flush()

        # Main sync in a separate transaction so we can commit incrementally
        async with db.begin():
            repo = SemgrepRuleRepository(db)
            source = await repo.get_source_by_id(source_id)
            run_result = await repo.get_latest_sync_run(source_id)
            if not source or not run_result:
                return

            settings = await _load_ingestion_settings(db)
            workdir = Path(settings["workdir"])

            try:
                await _run_sync_inner(source, run_result, repo, workdir)
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1000:]}"
                logger.error(
                    "semgrep.sync.failed",
                    extra={"source": source.slug, "error": str(exc)},
                    exc_info=True,
                )
                source.last_sync_status = "failed"
                source.last_sync_error = err_msg[:2000]
                run_result.status = "failed"
                run_result.error = err_msg[:2000]
                run_result.finished_at = datetime.now(tz=timezone.utc)


def _load_seed_sources() -> list[dict]:
    """Parse semgrep_sources.yaml. Returns list of source dicts."""
    import yaml as _yaml
    from importlib.resources import files

    try:
        seed_path = Path(__file__).parent.parent.parent.parent / "data" / "semgrep_sources.yaml"
        raw = _yaml.safe_load(seed_path.read_text(encoding="utf-8"))
        return raw.get("sources", [])
    except Exception as exc:
        logger.error("semgrep.sync.load_seed_failed", extra={"error": str(exc)})
        return []


async def refresh_source_seed() -> list[db_models.SemgrepRuleSource]:
    """Upsert all sources from semgrep_sources.yaml. Does not overwrite enabled/auto_sync."""
    sources_data = _load_seed_sources()
    results = []
    async with AsyncSessionLocal() as db:
        async with db.begin():
            repo = SemgrepRuleRepository(db)
            for sd in sources_data:
                source = await repo.upsert_source({
                    "slug": sd["slug"],
                    "display_name": sd["display_name"],
                    "description": sd.get("description", ""),
                    "repo_url": sd["repo_url"],
                    "branch": sd.get("branch", "main"),
                    "subpath": sd.get("subpath"),
                    "license_spdx": sd["license_spdx"],
                    "author": sd.get("author", ""),
                })
                results.append(source)
    return results
