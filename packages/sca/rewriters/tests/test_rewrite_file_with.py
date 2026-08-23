"""Contract tests for the shared ``rewrite_file_with`` driver."""

from __future__ import annotations

from pathlib import Path

import packages.sca.rewriters as rewriters
from packages.sca.rewriters import (
    RewriteEdit,
    RewriteResult,
    rewrite_file_with,
)


def _edit(loc: str, old: str = "1.0", new: str = "2.0") -> RewriteEdit:
    return RewriteEdit(locator=loc, old_value=old, new_value=new)


def _replace_apply_one(text: str, edit: RewriteEdit):
    """Replace ``<locator>=<old>`` with ``<locator>=<new>``."""
    needle = f"{edit.locator}={edit.old_value}"
    if needle in text:
        return (
            text.replace(needle, f"{edit.locator}={edit.new_value}", 1),
            RewriteResult(edit=edit, applied=True, reason=""),
        )
    return text, RewriteResult(edit=edit, applied=False, reason="not_found")


def test_edits_thread_through_evolving_text(tmp_path: Path):
    f = tmp_path / "manifest.txt"
    f.write_text("a=1.0\nb=1.0\n", encoding="utf-8")
    results = rewrite_file_with(
        f, [_edit("a"), _edit("b")], _replace_apply_one,
    )
    assert [r.applied for r in results] == [True, True]
    assert f.read_text(encoding="utf-8") == "a=2.0\nb=2.0\n"


def test_no_write_when_nothing_applied(tmp_path: Path):
    f = tmp_path / "manifest.txt"
    f.write_text("a=1.0\n", encoding="utf-8")
    before = f.stat().st_mtime_ns
    results = rewrite_file_with(f, [_edit("missing")], _replace_apply_one)
    assert [r.applied for r in results] == [False]
    assert results[0].reason == "not_found"
    assert f.stat().st_mtime_ns == before


def test_read_failure_fails_every_edit(tmp_path: Path):
    f = tmp_path / "absent.txt"
    results = rewrite_file_with(f, [_edit("a"), _edit("b")], _replace_apply_one)
    assert len(results) == 2
    assert all(not r.applied for r in results)
    assert all(r.reason.startswith("error: read failed") for r in results)


def test_write_failure_fails_only_applied_edits(tmp_path: Path, monkeypatch):
    f = tmp_path / "manifest.txt"
    f.write_text("a=1.0\n", encoding="utf-8")

    def _boom(path, text):
        raise OSError("disk full")

    monkeypatch.setattr(rewriters, "_atomic_write", _boom)
    results = rewrite_file_with(
        f, [_edit("a"), _edit("missing")], _replace_apply_one,
    )
    assert results[0].applied is False
    assert results[0].reason.startswith("error: write failed")
    # The edit that never applied keeps its own result untouched.
    assert results[1].reason == "not_found"
    assert f.read_text(encoding="utf-8") == "a=1.0\n"


def test_one_result_per_edit_in_order(tmp_path: Path):
    f = tmp_path / "manifest.txt"
    f.write_text("a=1.0\n", encoding="utf-8")
    edits = [_edit("missing"), _edit("a")]
    results = rewrite_file_with(f, edits, _replace_apply_one)
    assert [r.edit for r in results] == edits
