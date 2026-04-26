"""Unit tests for the SAST-prescan staging context manager.

The staging step is the M1 / M2 boundary: every attacker-controlled
filename must be reduced to a safe slug before any scanner sees it,
and the temp directory must be cleaned up even on exception.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.infrastructure.scanners.staging import (
    _safe_relative_path,
    stage_files,
)


def test_stage_files_writes_content_and_cleans_up():
    files = {"a/b.py": "print('hi')", "c.py": "x = 1\n"}
    seen_dir: Path | None = None
    with stage_files(files) as (staged_dir, original_paths):
        seen_dir = staged_dir
        assert staged_dir.exists()
        # Both files materialize under the temp dir.
        assert len(original_paths) == 2
        for staged_path, rel in original_paths.items():
            assert staged_path.exists()
            assert staged_path.is_file()
            assert staged_path.read_text() == files[rel]
    # Temp dir is removed after the context exits.
    assert seen_dir is not None
    assert not seen_dir.exists()


def test_stage_files_cleans_up_on_exception():
    files = {"x.py": "y = 2\n"}
    seen_dir: Path | None = None
    with pytest.raises(RuntimeError, match="boom"):
        with stage_files(files) as (staged_dir, _original_paths):
            seen_dir = staged_dir
            assert staged_dir.exists()
            raise RuntimeError("boom")
    assert seen_dir is not None
    assert not seen_dir.exists()


def test_safe_relative_path_strips_traversal_and_leading_slash():
    # `..` segments are dropped; absolute markers stripped; result is
    # relative and contains only sanitized components.
    assert _safe_relative_path("../../etc/passwd") == Path("etc/passwd")
    assert _safe_relative_path("/etc/passwd") == Path("etc/passwd")
    assert _safe_relative_path("./a/./b.py") == Path("a/b.py")


def test_safe_relative_path_neutralises_argv_injection_basename():
    # The literal filename `--config=/etc/passwd` must NOT survive
    # intact into the staged tree; if it did, scanner argv parsers
    # would reinterpret it as a flag.
    staged = _safe_relative_path("--config=/etc/passwd")
    assert "--config" not in str(staged)


def test_safe_relative_path_synthesizes_name_for_pure_junk():
    # Path containing only `..` resolves to no parts; the staging
    # helper substitutes an `unnamed` slug so the file is still
    # scannable.
    assert _safe_relative_path("../..") == Path("unnamed")


def test_stage_files_keeps_a_reverse_map_back_to_original_paths():
    files = {"src/handlers/user.py": "x = 1\n"}
    with stage_files(files) as (_staged_dir, original_paths):
        assert "src/handlers/user.py" in original_paths.values()


def test_stage_files_handles_basename_collisions():
    # Two files whose sanitized basenames collide (different content)
    # both persist via a sha1 disambiguator. Without that, the second
    # write would silently overwrite the first.
    files = {
        "a/--config=foo": "first\n",
        "b/--config=foo": "second\n",
    }
    with stage_files(files) as (_staged_dir, original_paths):
        contents = sorted(p.read_text() for p in original_paths.keys())
        assert contents == ["first\n", "second\n"]
