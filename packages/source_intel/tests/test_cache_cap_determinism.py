"""Edits past the content-hash cap must still invalidate the cache.

Pre-fix, ``_hash_target_tree`` collected files in ``rglob`` enumeration
order, capped the list at 5000, and only THEN sorted — so which files
participated was nondeterministic, and an edit to any file past the cap
never changed the hash. Post-fix every file's path + (mtime, size)
participates; only a deterministic sorted-path prefix is content-hashed.
"""

from __future__ import annotations

import time

import pytest

from packages.source_intel import cache as cache_mod
from packages.source_intel.cache import (
    _hash_target_tree,
    compute_target_signature,
)


@pytest.fixture()
def small_cap(monkeypatch):
    """Shrink the content budget so the past-cap path is exercised
    without creating 5000 fixture files."""
    monkeypatch.setattr(cache_mod, "_CONTENT_HASH_CAP", 1)


def _make_tree(tmp_path):
    for name in ("a.c", "b.c", "c.c"):
        (tmp_path / name).write_text(f"int {name[0]};")


class TestHashTargetTreePastCap:
    def test_edit_past_cap_flips_hash(self, tmp_path, small_cap):
        _make_tree(tmp_path)
        h1 = _hash_target_tree(tmp_path)
        # c.c sorts last — well past the (patched) content budget.
        time.sleep(0.01)
        (tmp_path / "c.c").write_text("int c; int extra;")
        h2 = _hash_target_tree(tmp_path)
        assert h1 != h2

    def test_file_added_past_cap_flips_hash(self, tmp_path, small_cap):
        _make_tree(tmp_path)
        h1 = _hash_target_tree(tmp_path)
        (tmp_path / "z.c").write_text("int z;")
        h2 = _hash_target_tree(tmp_path)
        assert h1 != h2

    def test_unchanged_tree_is_stable(self, tmp_path, small_cap):
        _make_tree(tmp_path)
        assert _hash_target_tree(tmp_path) == _hash_target_tree(tmp_path)


class TestSignatureHasNoCap:
    def test_every_file_participates(self, tmp_path):
        # The stat-only signature walks every file; an edit to the
        # lexicographically-last file must flip it.
        for i in range(10):
            (tmp_path / f"f{i:02d}.c").write_text("int x;")
        s1 = compute_target_signature(tmp_path)
        time.sleep(0.01)
        (tmp_path / "f09.c").write_text("int x; int y;")
        s2 = compute_target_signature(tmp_path)
        assert s1 != s2
