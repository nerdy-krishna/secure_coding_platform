# src/app/core/services/semgrep_ingestion/validator.py
import asyncio
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

_VALIDATE_TIMEOUT = 30  # seconds per file


def _semgrep_binary() -> str:
    binary = shutil.which("semgrep") or "/opt/semgrep-venv/bin/semgrep"
    return binary


def _sync_validate(file_path: str) -> tuple[bool, str]:
    import subprocess
    try:
        result = subprocess.run(
            [_semgrep_binary(), "--validate", "--config", file_path, "--metrics=off"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=_VALIDATE_TIMEOUT,
        )
        if result.returncode == 0:
            return True, ""
        stderr = (result.stderr or result.stdout or "")[:500]
        return False, stderr
    except subprocess.TimeoutExpired:
        return False, "validation timed out"
    except Exception as exc:
        return False, str(exc)


async def validate_rule_file(path: Path) -> bool:
    """Run semgrep --validate on a single file. Returns True if valid."""
    ok, reason = await asyncio.to_thread(_sync_validate, str(path))
    if not ok:
        logger.debug(
            "semgrep.validator.invalid",
            extra={"path": str(path), "reason": reason[:200]},
        )
    return ok
