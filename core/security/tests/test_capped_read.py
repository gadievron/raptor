"""Contract tests for ``core.security.capped_read.read_capped``."""

from __future__ import annotations

import os

from core.security.capped_read import read_capped


def test_reads_file_within_cap(tmp_path):
    f = tmp_path / "cfg"
    f.write_bytes(b"hello")
    assert read_capped(f, 10) == b"hello"


def test_exactly_cap_is_allowed(tmp_path):
    f = tmp_path / "cfg"
    f.write_bytes(b"x" * 10)
    assert read_capped(f, 10) == b"x" * 10


def test_over_cap_returns_none(tmp_path):
    f = tmp_path / "cfg"
    f.write_bytes(b"x" * 11)
    assert read_capped(f, 10) is None


def test_missing_file_returns_none(tmp_path):
    assert read_capped(tmp_path / "absent", 10) is None


def test_symlink_not_followed(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"secret")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert read_capped(link, 100) is None


def test_fifo_returns_none_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert read_capped(fifo, 100) is None


def test_directory_returns_none(tmp_path):
    assert read_capped(tmp_path, 100) is None
