# src/app/core/services/semgrep_ingestion/validator.py
import asyncio
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

_VALIDATE_TIMEOUT = 30  # seconds per file


def _semgrep_binary() -> str | None:
    binary = shutil.which("semgrep")
    if binary:
        return binary
    fallback = "/opt/semgrep-venv/bin/semgrep"
    if shutil.which(fallback) or Path(fallback).exists():
        return fallback
    return None


def _structural_validate(file_path: str) -> tuple[bool, str]:
    """Minimal YAML + rules-key check used when semgrep binary is unavailable."""
    import yaml

    try:
        with open(file_path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict):
            return False, "not a YAML mapping"
        rules = doc.get("rules")
        if not isinstance(rules, list) or not rules:
            return False, "missing or empty 'rules' key"
        for rule in rules:
            if not isinstance(rule, dict) or "id" not in rule:
                return False, "rule missing 'id' field"
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _sync_validate(file_path: str) -> tuple[bool, str]:
    import subprocess

    binary = _semgrep_binary()
    if binary is None:
        # semgrep not installed — fall back to structural YAML check
        logger.warning(
            "semgrep.validator.binary_missing",
            extra={"fallback": "structural_yaml_check"},
        )
        return _structural_validate(file_path)

    try:
        result = subprocess.run(
            [binary, "--validate", "--config", file_path, "--metrics=off"],
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
    except FileNotFoundError:
        logger.warning(
            "semgrep.validator.binary_not_executable", extra={"binary": binary}
        )
        return _structural_validate(file_path)
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
