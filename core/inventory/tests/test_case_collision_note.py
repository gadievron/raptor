"""Tests for the inventory case-collision note (WSL drvfs/9p).

The note is awareness-only: it fires as one informational log line
when the built file list carries paths differing only by case AND the
target sits on a case-insensitive-suspect mount. Keying never changes.
Hermetic: the WSL detection and the mount probe are mocked as
``core.startup.wsl`` module attributes (never env vars).
"""

from __future__ import annotations

import logging
from unittest import mock

import pytest

from core.inventory.builder import (
    _CASE_COLLISION_EXAMPLE_CAP,
    _note_case_collisions,
    build_inventory,
)
from core.startup import wsl

pytestmark = pytest.mark.wsl


def _files(*paths: str) -> list[dict]:
    return [{"path": p} for p in paths]


class TestNoteCaseCollisions:
    def test_collision_on_interop_mount_logs_one_note(self, caplog):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True), \
             caplog.at_level(logging.INFO, logger="core.inventory.builder"):
            _note_case_collisions(
                "/repo", _files("src/Foo.c", "src/foo.c", "src/bar.c"),
            )
        notes = [r for r in caplog.records
                 if "differ only by case" in r.getMessage()]
        assert len(notes) == 1
        msg = notes[0].getMessage()
        assert "src/Foo.c" in msg
        assert "src/foo.c" in msg
        assert "src/bar.c" not in msg
        assert "keying unchanged" in msg
        assert "docs/wsl.md" in msg

    def test_silent_off_wsl_and_probe_not_paid(self, caplog):
        probe = mock.Mock()
        with mock.patch.object(wsl, "is_wsl", return_value=False), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p", probe), \
             caplog.at_level(logging.INFO):
            _note_case_collisions("/repo", _files("Foo.c", "foo.c"))
        assert "differ only by case" not in caplog.text
        probe.assert_not_called()

    def test_silent_on_case_sensitive_mount(self, caplog):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=False), \
             caplog.at_level(logging.INFO):
            _note_case_collisions("/repo", _files("Foo.c", "foo.c"))
        assert "differ only by case" not in caplog.text

    def test_silent_without_collisions(self, caplog):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True), \
             caplog.at_level(logging.INFO):
            _note_case_collisions("/repo", _files("a.c", "b.c", "c.c"))
        assert "differ only by case" not in caplog.text

    def test_examples_capped_with_more_tail(self, caplog):
        groups = []
        for i in range(_CASE_COLLISION_EXAMPLE_CAP + 2):
            groups += [f"dir/file{i}.c", f"dir/FILE{i}.c"]
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True), \
             caplog.at_level(logging.INFO):
            _note_case_collisions("/repo", _files(*groups))
        notes = [r.getMessage() for r in caplog.records
                 if "differ only by case" in r.getMessage()]
        assert len(notes) == 1
        assert f"{_CASE_COLLISION_EXAMPLE_CAP + 2} path group(s)" in notes[0]
        assert "(+2 more)" in notes[0]

    def test_group_spellings_capped_at_three(self, caplog):
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True), \
             caplog.at_level(logging.INFO):
            _note_case_collisions(
                "/repo", _files("x.c", "X.c", "x.C", "X.C"),
            )
        notes = [r.getMessage() for r in caplog.records
                 if "differ only by case" in r.getMessage()]
        assert len(notes) == 1
        assert notes[0].count(".c") + notes[0].count(".C") == 3

    def test_hostile_path_bytes_escaped(self, caplog):
        hostile = "src/\x1b]0;pwned\x07Foo.c"
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True), \
             caplog.at_level(logging.INFO):
            _note_case_collisions(
                "/repo", _files(hostile, hostile.lower()),
            )
        notes = [r.getMessage() for r in caplog.records
                 if "differ only by case" in r.getMessage()]
        assert len(notes) == 1
        assert "\x1b" not in notes[0]
        assert "\x07" not in notes[0]

    def test_keying_untouched(self):
        files = _files("Foo.c", "foo.c")
        snapshot = [dict(f) for f in files]
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True):
            _note_case_collisions("/repo", files)
        assert files == snapshot

    def test_never_raises(self):
        with mock.patch.object(wsl, "is_wsl",
                               side_effect=RuntimeError("boom")):
            _note_case_collisions("/repo", _files("Foo.c", "foo.c"))


class TestBuildInventoryIntegration:
    def test_note_fires_from_build_inventory(self, tmp_path, caplog):
        # Case-SENSITIVE host filesystems hold both spellings as real
        # files; the mount verdict is mocked, so the pass exercises
        # the real build path end-to-end without a WSL host.
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Foo.c").write_text("int a(void) { return 1; }\n")
        (repo / "foo.c").write_text("int b(void) { return 2; }\n")
        out = tmp_path / "out"
        with mock.patch.object(wsl, "is_wsl", return_value=True), \
             mock.patch.object(wsl, "fs_is_drvfs_or_9p",
                               return_value=True), \
             caplog.at_level(logging.INFO, logger="core.inventory.builder"):
            inv = build_inventory(
                str(repo), output_dir=str(out), parallel=False,
            )
        assert "differ only by case" in caplog.text
        # Keying unchanged: both spellings stay distinct entries.
        paths = {f["path"] for f in inv["files"]}
        assert {"Foo.c", "foo.c"} <= paths
