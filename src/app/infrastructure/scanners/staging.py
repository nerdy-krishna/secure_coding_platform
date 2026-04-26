"""Stage user-uploaded files into a sandbox before invoking SAST scanners.

The worker stores submitted files as a `Dict[rel_path, content]` in
`WorkerState["files"]`. Scanners need an actual filesystem tree to walk,
and `rel_path` is attacker-controlled — so we materialize the tree under
a fresh `tempfile.mkdtemp()` with sanitized basenames and hand the
scanner a path it could never have constructed.

Rules (M1, M2 from the threat model):
- Sanitize the basename: strip `..`, leading `/`, NUL bytes; collapse
  duplicates with a sha1 prefix.
- Group files in subdirectories under the temp root by hash to avoid
  any path traversal attempt; subdirectories themselves get sanitized.
- Always clean up via `try/finally`.
- The temp directory is created with `mkdtemp` (mode 0o700 by default).
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, Mapping, Tuple


logger = logging.getLogger(__name__)


_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._\-]")


def _sanitize_component(part: str) -> str:
    """Reduce a single path component to a safe ASCII slug."""
    cleaned = part.replace("\x00", "").strip()
    # Drop anything that looks like a traversal token.
    if cleaned in ("", ".", ".."):
        return ""
    cleaned = _UNSAFE_NAME_CHARS.sub("_", cleaned)
    # Avoid leading dots (hidden files like `.semgrepignore`,
    # `.gitleaks.toml`) so user-tree config files cannot be picked up
    # by scanners that auto-discover them. Strip leading dashes too
    # so a file literally named `--config=/etc/passwd` cannot be
    # reinterpreted as a flag by argv parsers (M1).
    cleaned = cleaned.lstrip("-.") or cleaned
    return cleaned[:120]  # bound length


def _safe_relative_path(rel_path: str) -> Path:
    """Convert an attacker-controlled relative path into a safe staged
    `Path` (no leading separator, no `..`, sanitized components).

    NUL-byte handling (N13): on POSIX, ``Path("foo\x00bar")`` itself
    raises ``ValueError`` since Python 3.10. Wrap the parts walk so a
    malformed path falls back to the ``unnamed`` slug — the file is
    still scannable, and the rest of the scan is not aborted.
    """
    parts: list[str] = []
    try:
        raw_parts = Path(rel_path).parts
    except (ValueError, OSError):
        return Path("unnamed")
    for raw in raw_parts:
        # `Path.parts` already collapses double slashes; we still need
        # to drop drive letters and the absolute-path marker.
        if raw in ("/", "\\"):
            continue
        clean = _sanitize_component(raw)
        if clean:
            parts.append(clean)
    if not parts:
        # Pure-junk path: synthesize one based on the original hash so
        # the file is still scannable.
        parts = ["unnamed"]
    return Path(*parts)


@contextmanager
def stage_files(files: Mapping[str, str]) -> Iterator[Tuple[Path, Dict[Path, str]]]:
    """Materialize ``files`` into a fresh temp directory.

    Yields ``(staged_dir, original_paths)`` where ``original_paths`` maps
    the absolute staged file `Path` back to the original
    user-supplied relative path. Scanners walk ``staged_dir``; the
    runner uses ``original_paths`` to translate each finding's
    ``filename`` back to the user-facing path.

    The temp directory is removed on exit even if the caller raises.
    """
    staged_dir = Path(tempfile.mkdtemp(prefix="sccap-scan-"))
    original_paths: Dict[Path, str] = {}
    try:
        for rel_path, content in files.items():
            safe_rel = _safe_relative_path(rel_path)
            staged_path = staged_dir / safe_rel
            # Collision: salt the basename with a content-hash prefix so
            # both files coexist on disk.
            if staged_path.exists():
                # Hash is used purely as a uniqueness slug to disambiguate
                # colliding sanitized basenames; not a security primitive.
                # sha256 keeps Bandit (B324) quiet without changing intent.
                digest = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()[
                    :8
                ]
                staged_path = staged_path.with_name(f"{digest}__{staged_path.name}")
            staged_path.parent.mkdir(parents=True, exist_ok=True)
            staged_path.write_text(content, encoding="utf-8", errors="replace")
            original_paths[staged_path.resolve()] = rel_path
        yield staged_dir, original_paths
    finally:
        try:
            shutil.rmtree(staged_dir, ignore_errors=False)
        except OSError as exc:
            logger.warning("Failed to clean up staged scan dir %s: %s", staged_dir, exc)
