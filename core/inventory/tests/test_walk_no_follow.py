"""Untrusted-target enumeration must not follow directory symlinks.

header/macro enrichment reads file content into audit prompts; a
hostile target shipping ``dir -> /`` walked the host filesystem on
Python < 3.13 via ``Path.rglob``. These pin the ``os.walk``-based
walker and the three consumer indexes.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.inventory._walk import iter_regular_files
from core.inventory.header_functions import build_header_function_index
from core.inventory.macro_resolve import (
    build_macro_table,
    build_rust_macro_table,
)


def _hostile_target(tmp_path: Path, suffix: str, content: str) -> Path:
    """target/real/<in>.suffix + target/escape -> outside dir with a
    matching file."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / f"host{suffix}").write_text(content, encoding="utf-8")
    target = tmp_path / "target"
    (target / "real").mkdir(parents=True)
    (target / "real" / f"in{suffix}").write_text(content, encoding="utf-8")
    os.symlink(outside, target / "escape")
    return target


class TestIterRegularFiles:
    def test_directory_symlink_not_entered(self, tmp_path):
        target = _hostile_target(tmp_path, ".h", "int x;\n")
        names = {p.name for p in iter_regular_files(target, {".h"})}
        assert names == {"in.h"}

    def test_file_symlink_skipped(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        (target / "a.h").write_text("x", encoding="utf-8")
        os.symlink(target / "a.h", target / "linked.h")
        names = {p.name for p in iter_regular_files(target, {".h"})}
        assert names == {"a.h"}  # per-file symlink filter preserved

    def test_cap_truncates(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        for i in range(10):
            (target / f"f{i}.h").write_text("x", encoding="utf-8")
        assert len(list(iter_regular_files(target, {".h"}, max_files=3))) == 3

    def test_cap_leaves_small_trees_complete(self, tmp_path):
        # Other direction: under the cap, nothing is dropped.
        target = tmp_path / "t"
        target.mkdir()
        for i in range(10):
            (target / f"f{i}.h").write_text("x", encoding="utf-8")
        assert len(list(iter_regular_files(target, {".h"}, max_files=100))) == 10


class TestConsumersContained:
    def test_header_index_ignores_symlinked_dir(self, tmp_path):
        target = _hostile_target(
            tmp_path, ".h",
            "static int helper(void)\n{\n    return 1;\n}\n",
        )
        index = build_header_function_index(target)
        assert all(not rel.startswith("escape") for rel, _ in index.values())

    def test_c_macro_table_ignores_symlinked_dir(self, tmp_path):
        target = _hostile_target(tmp_path, ".h", "#define HOSTMARK 42\n")
        # The in-tree copy defines the macro too, so presence alone
        # proves nothing; assert the walk never left the target by
        # planting a macro that exists ONLY outside.
        outside_only = tmp_path / "outside" / "only.h"
        outside_only.write_text("#define OUTSIDE_ONLY 1\n", encoding="utf-8")
        table = build_macro_table(target)
        assert "OUTSIDE_ONLY" not in table
        assert "HOSTMARK" in table  # in-tree copy still indexed

    def test_rust_macro_table_ignores_symlinked_dir(self, tmp_path):
        target = _hostile_target(
            tmp_path, ".rs",
            "macro_rules! inmac { () => {} }\n",
        )
        (tmp_path / "outside" / "only.rs").write_text(
            "macro_rules! outmac { () => {} }\n", encoding="utf-8",
        )
        table = build_rust_macro_table(target)
        assert "outmac" not in table
        assert "inmac" in table


class TestScanBudget:
    def test_scan_cap_bounds_nonmatching_walk(self, tmp_path, monkeypatch):
        # The yield cap alone let a hostile tree of NON-matching names
        # walk in full — the wall-time half of the file-farm class.
        import core.inventory._walk as walk_mod

        for i in range(30):
            (tmp_path / f"junk{i}.bin").write_text("")
        (tmp_path / "real.h").write_text("int x;\n")
        monkeypatch.setattr(walk_mod, "_MAX_WALK_SCAN", 10)
        found = list(walk_mod.iter_regular_files(tmp_path, {".h"}))
        # Bounded: at most the first 10 entries were examined.
        assert len(found) <= 1

    def test_scan_cap_leaves_normal_trees_complete(self, tmp_path):
        import core.inventory._walk as walk_mod

        for i in range(5):
            (tmp_path / f"f{i}.h").write_text("int x;\n")
        found = list(walk_mod.iter_regular_files(tmp_path, {".h"}))
        assert len(found) == 5
