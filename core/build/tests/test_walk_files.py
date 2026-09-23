"""Recursive enumeration over the untrusted repo — symlink and cap
containment.

Detection and synthesis run in the UNSANDBOXED parent, so the walk
itself is a security boundary: a scanned repo containing ``src -> /``
must not steer enumeration into the host filesystem
(``Path.rglob`` follows directory symlinks on Python < 3.13), and a
hostile file farm must not monopolise detection wall time.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.build.build_detector import BuildDetector, _walk_files


def _tree(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.c").write_text("int a;\n", encoding="utf-8")
    (root / "src" / "b.h").write_text("// h\n", encoding="utf-8")


class TestWalkFiles:
    def test_directory_symlink_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "host.c").write_text("int host;\n", encoding="utf-8")
        repo = tmp_path / "repo"
        _tree(repo)
        os.symlink(outside, repo / "escape")

        found = _walk_files(repo, (".c",))
        names = {p.name for p in found}
        assert "a.c" in names
        assert "host.c" not in names, (
            "enumeration followed a directory symlink out of the repo"
        )

    def test_file_symlink_still_yielded(self, tmp_path):
        # rglob parity: symlinks to FILES keep appearing in listings.
        repo = tmp_path / "repo"
        _tree(repo)
        os.symlink(repo / "src" / "a.c", repo / "linked.c")
        names = {p.name for p in _walk_files(repo, (".c",))}
        assert {"a.c", "linked.c"} <= names

    def test_suffix_filter_case_sensitive(self, tmp_path):
        repo = tmp_path / "repo"
        _tree(repo)
        (repo / "src" / "UPPER.C").write_text("int u;\n", encoding="utf-8")
        names = {p.name for p in _walk_files(repo, (".c",))}
        assert "UPPER.C" not in names  # rglob("*.c") parity on Linux

    def test_cap_truncates_with_room_to_spare(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        for i in range(10):
            (repo / f"f{i}.c").write_text("", encoding="utf-8")
        capped = _walk_files(repo, (".c",), max_files=3)
        assert len(capped) == 3

    def test_cap_leaves_small_trees_complete(self, tmp_path):
        # Other direction: a tree under the cap is enumerated fully —
        # a too-aggressive cap would silently drop real source files.
        repo = tmp_path / "repo"
        repo.mkdir()
        for i in range(10):
            (repo / f"f{i}.c").write_text("", encoding="utf-8")
        assert len(_walk_files(repo, (".c",), max_files=100)) == 10


class TestDetectParamsContainment:
    def test_symlinked_out_sources_not_compiled(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "host.c").write_text("int host;\n", encoding="utf-8")
        repo = tmp_path / "repo"
        _tree(repo)
        os.symlink(outside, repo / "vendor")

        sources, _compiler, _inc, _def = (
            BuildDetector(repo)._detect_build_params("cpp")
        )
        names = {p.name for p in sources}
        assert "a.c" in names
        assert "host.c" not in names


def test_directory_cap_bounds_empty_dir_farms(tmp_path, monkeypatch, caplog):
    """The file cap bounds files COLLECTED, not directories visited —
    an empty-directory farm walked unbounded before the dir cap."""
    import logging

    from core.build import build_detector as bd

    farm = tmp_path / "farm"
    for i in range(12):
        d = farm / f"d{i:02d}"
        d.mkdir(parents=True)
        # One file per dir: past the cap, files stop being collected
        # (os.walk order is arbitrary, so assert on the COUNT).
        (d / "x.c").write_text("")
    monkeypatch.setattr(bd, "_MAX_WALK_DIRS", 5)
    with caplog.at_level(logging.WARNING):
        out = bd._walk_files(farm, (".c",))
    assert len(out) < 12
    assert any("dir cap" in r.message for r in caplog.records)


def test_directory_cap_generous_for_real_trees(tmp_path):
    from core.build import build_detector as bd

    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "x.c").write_text("")
    out = bd._walk_files(tmp_path, (".c",))
    assert len(out) == 1
