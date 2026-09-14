"""Incremental reuse must be content-gated, not stat-gated.

A same-size edit with a preserved mtime (rsync -a, cp -p, archive
extraction, os.utime restore) is invisible to a [mtime_ns, size]
compare; serving the old parsed entry attaches coverage marks and span
hashes to code that no longer exists. Reuse must go through the
SHA-256 compare (the documented contract) — while a genuine content
match must still skip re-parsing (the fast path's whole point).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.inventory import builder
from core.inventory.builder import _process_single_file


def _entry_for(filepath: Path, target: Path) -> dict:
    return _process_single_file(filepath, target, [])


def test_same_stat_different_content_is_reparsed(tmp_path):
    target = tmp_path
    f = target / "mod.py"
    f.write_text("def old_name():\n    return 1\n", encoding="utf-8")
    old_entry = _entry_for(f, target)
    assert old_entry and old_entry["items"][0]["name"] == "old_name"
    st = f.stat()

    # Same-length different content, mtime restored — the
    # timestamp-preserving-sync shape.
    f.write_text("def new_name():\n    return 1\n", encoding="utf-8")
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert [f.stat().st_mtime_ns, f.stat().st_size] == old_entry["_stat"]

    fresh = _process_single_file(
        f, target, [], old_files={"mod.py": old_entry},
    )
    names = [i["name"] for i in fresh["items"]]
    assert "new_name" in names and "old_name" not in names, (
        "stat-matching stale entry was served for changed content"
    )


def test_unchanged_content_still_skips_parsing(tmp_path, monkeypatch):
    # Other direction: content-identical files must reuse the old
    # entry WITHOUT re-parsing — the sha gate keeps the expensive
    # stage skipped.
    target = tmp_path
    f = target / "mod.py"
    f.write_text("def keep():\n    return 1\n", encoding="utf-8")
    old_entry = _entry_for(f, target)

    def _no_parse(*args, **kwargs):
        raise AssertionError("unchanged file was re-parsed")

    monkeypatch.setattr(builder, "extract_items", _no_parse)
    reused = _process_single_file(
        f, target, [], old_files={"mod.py": old_entry},
    )
    assert reused is old_entry


def test_changed_stat_changed_content_reparsed(tmp_path):
    target = tmp_path
    f = target / "mod.py"
    f.write_text("def a():\n    return 1\n", encoding="utf-8")
    old_entry = _entry_for(f, target)
    f.write_text("def b():\n    return 2\n\n# grew\n", encoding="utf-8")
    fresh = _process_single_file(
        f, target, [], old_files={"mod.py": old_entry},
    )
    assert [i["name"] for i in fresh["items"] if i["name"] in ("a", "b")] == ["b"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
