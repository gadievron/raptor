"""The anonymous-workspace harvest helpers.

The source dir was the sandboxed child's write grant, so every name in
it is attacker-influenced — the helpers must refuse planted symlinks,
must not block on planted FIFOs, and must write fresh 0600 inodes so a
pre-planted file at the predictable destination name is displaced.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from packages.web.harvest import harvest_regular_file, harvest_tree

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file-mode semantics",
)


def test_copies_regular_file_as_fresh_0600_inode(tmp_path: Path):
    src = tmp_path / "ws" / "report.json"
    src.parent.mkdir()
    src.write_text('{"results": []}', encoding="utf-8")
    dst = tmp_path / "run" / "report.json"
    dst.parent.mkdir()
    # Pre-planted world-readable file at the destination name must be
    # displaced, not appended to or left at its old mode. (The inode
    # number itself may be recycled by the filesystem, so the pin is
    # content + mode, not st_ino.)
    dst.write_text("stale", encoding="utf-8")
    dst.chmod(0o644)

    assert harvest_regular_file(src, dst) is True
    assert dst.read_text(encoding="utf-8") == '{"results": []}'
    assert dst.stat().st_mode & 0o777 == 0o600


def test_missing_source_is_a_quiet_noop(tmp_path: Path):
    dst = tmp_path / "report.json"
    assert harvest_regular_file(tmp_path / "absent", dst) is False
    assert not dst.exists()


def test_refuses_planted_symlink_source(tmp_path: Path):
    secret = tmp_path / "secret"
    secret.write_text("hostage", encoding="utf-8")
    link = tmp_path / "report.json"
    link.symlink_to(secret)
    dst = tmp_path / "out.json"

    assert harvest_regular_file(link, dst) is False
    assert not dst.exists()


def test_planted_fifo_does_not_block_the_parent(tmp_path: Path):
    """O_NONBLOCK is load-bearing: without it, open(2) on a FIFO with
    no writer blocks forever and the S_ISREG check is never reached.
    This test HANGS (then times out) on a helper missing the flag."""
    fifo = tmp_path / "report.json"
    os.mkfifo(fifo)
    dst = tmp_path / "out.json"

    assert harvest_regular_file(fifo, dst) is False
    assert not dst.exists()


def test_tree_mirrors_dirs_0700_and_skips_symlinks(tmp_path: Path):
    src = tmp_path / "ws" / "responses"
    (src / "example.test").mkdir(parents=True)
    (src / "example.test" / "req1.txt").write_text("GET /", encoding="utf-8")
    secret = tmp_path / "secret"
    secret.write_text("hostage", encoding="utf-8")
    # Planted escapes: a symlinked file and a symlinked dir inside the
    # child-written tree.
    (src / "example.test" / "link.txt").symlink_to(secret)
    (src / "linked-dir").symlink_to(tmp_path)
    dst = tmp_path / "run" / "responses"

    harvest_tree(src, dst)

    assert (dst / "example.test" / "req1.txt").read_text(
        encoding="utf-8") == "GET /"
    assert dst.stat().st_mode & 0o777 == 0o700
    assert (dst / "example.test").stat().st_mode & 0o777 == 0o700
    assert (dst / "example.test" / "req1.txt").stat().st_mode & 0o777 == 0o600
    assert not (dst / "example.test" / "link.txt").exists()
    assert not (dst / "linked-dir").exists()


def test_tree_displaces_planted_symlink_at_destination_dir(tmp_path: Path):
    """A pre-conversion child wrote directly into the run dir and could
    leave a symlink at the predictable store name; mkdir(exist_ok=True)
    would follow it and route every harvested file elsewhere."""
    src = tmp_path / "ws" / "responses"
    src.mkdir(parents=True)
    (src / "req1.txt").write_text("GET /", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    dst = tmp_path / "run" / "responses"
    dst.parent.mkdir()
    dst.symlink_to(elsewhere)

    harvest_tree(src, dst)

    assert not dst.is_symlink()
    assert (dst / "req1.txt").read_text(encoding="utf-8") == "GET /"
    assert list(elsewhere.iterdir()) == []


def test_tree_missing_source_is_a_quiet_noop(tmp_path: Path):
    dst = tmp_path / "run" / "responses"
    harvest_tree(tmp_path / "absent", dst)
    assert not dst.exists()
