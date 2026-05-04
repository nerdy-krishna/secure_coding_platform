# src/app/core/services/semgrep_ingestion/fetcher.py
import asyncio
import logging
import re
from pathlib import Path

import git
from git.exc import GitCommandError, InvalidGitRepositoryError

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

_HTTPS_URL_RE = re.compile(r"^https://[a-zA-Z0-9._/\-]+$")
_CLONE_TIMEOUT = 300  # seconds


def _validate_repo_url(url: str) -> None:
    if not _HTTPS_URL_RE.match(url):
        raise ValueError(f"Invalid repo_url (must be HTTPS, no query string): {url!r}")


def _sync_clone_or_pull(repo_url: str, branch: str, dest: Path) -> str:
    """Blocking git operation. Runs inside asyncio.to_thread."""
    if dest.exists() and (dest / ".git").exists():
        try:
            repo = git.Repo(dest)
            origin = repo.remotes["origin"]
            origin.fetch(branch)
            repo.git.reset("--hard", f"origin/{branch}")
            sha = repo.head.commit.hexsha
            logger.info(
                "semgrep.fetcher.pulled",
                extra={"dest": str(dest), "sha": sha[:8]},
            )
            return sha
        except (GitCommandError, InvalidGitRepositoryError) as exc:
            logger.warning(
                "semgrep.fetcher.pull_failed_recloning",
                extra={"dest": str(dest), "error": str(exc)},
            )
            import shutil

            shutil.rmtree(dest, ignore_errors=True)

    dest.parent.mkdir(parents=True, exist_ok=True)
    repo = git.Repo.clone_from(
        repo_url,
        dest,
        branch=branch,
        depth=1,
        multi_options=["--single-branch"],
    )
    sha = repo.head.commit.hexsha
    logger.info(
        "semgrep.fetcher.cloned",
        extra={"url": repo_url, "branch": branch, "sha": sha[:8]},
    )
    return sha


async def clone_or_pull(source: db_models.SemgrepRuleSource, workdir: Path) -> str:
    """Clone or update the rule repo. Returns HEAD SHA."""
    _validate_repo_url(source.repo_url)
    dest = workdir / source.slug
    try:
        sha = await asyncio.wait_for(
            asyncio.to_thread(
                _sync_clone_or_pull, source.repo_url, source.branch, dest
            ),
            timeout=_CLONE_TIMEOUT,
        )
    except asyncio.TimeoutError:
        raise RuntimeError(
            f"git operation timed out after {_CLONE_TIMEOUT}s for source {source.slug!r}"
        )
    return sha
