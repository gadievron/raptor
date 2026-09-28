"""Tests for core.source.gated — the raising-flavor gated reader.

The promotion contract: one body serves both ``core.json.utils``
(via ``budget_error=JsonBudgetExceededError``) and non-JSON strict
readers; every refusal class keeps its distinct exception shape.
"""

import os
import stat

import pytest

from core.source.gated import (
    ReadBudgetExceededError,
    open_regular_gated,
    read_bytes_gated,
    read_text_gated,
)


class TestReadTextGated:
    def test_reads_full_text(self, tmp_path):
        p = tmp_path / "a.txt"
        p.write_text("hello\nworld\n")
        assert read_text_gated(p, 1024) == "hello\nworld\n"

    def test_unbounded_none_budget(self, tmp_path):
        p = tmp_path / "a.txt"
        p.write_text("x" * 100)
        assert read_text_gated(p, None) == "x" * 100

    def test_bom_stripped_by_default(self, tmp_path):
        p = tmp_path / "bom.txt"
        p.write_bytes(b"\xef\xbb\xbfpayload")
        assert read_text_gated(p, 1024) == "payload"

    def test_explicit_utf8_keeps_bom(self, tmp_path):
        p = tmp_path / "bom.txt"
        p.write_bytes(b"\xef\xbb\xbfpayload")
        assert read_text_gated(p, 1024, encoding="utf-8") == "﻿payload"

    def test_over_budget_raises_budget_error(self, tmp_path):
        p = tmp_path / "big.txt"
        p.write_text("x" * 64)
        with pytest.raises(ReadBudgetExceededError) as exc:
            read_text_gated(p, 8)
        assert "max_bytes=8" in str(exc.value)

    def test_budget_error_is_value_error(self):
        assert issubclass(ReadBudgetExceededError, ValueError)

    def test_custom_budget_error_class(self, tmp_path):
        class MyBudget(ValueError):
            pass

        p = tmp_path / "big.txt"
        p.write_text("x" * 64)
        with pytest.raises(MyBudget):
            read_text_gated(p, 8, budget_error=MyBudget)

    def test_grow_recheck_refuses(self, tmp_path, monkeypatch):
        """A file that grows between fstat and read is refused, not
        buffered unbounded (the GROW gate)."""
        p = tmp_path / "grow.txt"
        p.write_text("ab")
        real_fstat = os.fstat

        def grow_after_fstat(fd):
            st = real_fstat(fd)
            with p.open("a") as fh:  # raw-open: test fixture grows its own tmp file
                fh.write("Z" * 64)
            return st

        monkeypatch.setattr(os, "fstat", grow_after_fstat)
        with pytest.raises(ReadBudgetExceededError, match="grew"):
            read_text_gated(p, 4)

    def test_missing_file_oserror(self, tmp_path):
        with pytest.raises(OSError):
            read_text_gated(tmp_path / "absent.txt", 8)

    def test_fifo_refused_not_hung(self, tmp_path):
        """A reader-less FIFO refuses (ValueError) instead of blocking
        — O_NONBLOCK on the open plus fd-checked regularity."""
        fifo = tmp_path / "wedge.txt"
        os.mkfifo(fifo)
        with pytest.raises(ValueError, match="not a regular file"):
            read_text_gated(fifo, 1024)

    def test_directory_refused(self, tmp_path):
        with pytest.raises((ValueError, OSError)):
            read_text_gated(tmp_path, 1024)

    def test_symlink_followed_by_default(self, tmp_path):
        target = tmp_path / "real.txt"
        target.write_text("via-link")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        assert read_text_gated(link, 1024) == "via-link"

    def test_nofollow_refuses_symlink(self, tmp_path):
        target = tmp_path / "real.txt"
        target.write_text("via-link")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        with pytest.raises(OSError):
            read_text_gated(link, 1024, follow_symlinks=False)

    def test_symlink_to_fifo_refused_even_following(self, tmp_path):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        assert stat.S_ISFIFO(os.stat(fifo).st_mode)
        link = tmp_path / "link"
        link.symlink_to(fifo)
        with pytest.raises(ValueError, match="not a regular file"):
            read_text_gated(link, 1024)

    def test_undecodable_bytes_raise_unicode_error(self, tmp_path):
        p = tmp_path / "bin.txt"
        p.write_bytes(b"\xff\xfe\xff")
        with pytest.raises(UnicodeDecodeError):
            read_text_gated(p, 1024)


class TestReadBytesGated:
    """The bytes flavor: one body carries the gates for both flavors,
    so every refusal class must hold without the decode step."""

    def test_reads_raw_bytes_undecoded(self, tmp_path):
        p = tmp_path / "bin.dat"
        p.write_bytes(b"\xff\xfe\x00payload")
        assert read_bytes_gated(p, 1024) == b"\xff\xfe\x00payload"

    def test_bom_not_stripped(self, tmp_path):
        p = tmp_path / "bom.dat"
        p.write_bytes(b"\xef\xbb\xbfpayload")
        assert read_bytes_gated(p, 1024) == b"\xef\xbb\xbfpayload"

    def test_over_budget_raises_budget_error(self, tmp_path):
        p = tmp_path / "big.dat"
        p.write_bytes(b"x" * 64)
        with pytest.raises(ReadBudgetExceededError):
            read_bytes_gated(p, 8)

    def test_fifo_refused_not_hung(self, tmp_path):
        fifo = tmp_path / "wedge.dat"
        os.mkfifo(fifo)
        with pytest.raises(ValueError, match="not a regular file"):
            read_bytes_gated(fifo, 1024)

    def test_symlink_to_device_refused(self, tmp_path):
        dev = "/dev/zero"
        if not os.path.exists(dev):
            pytest.skip("no /dev/zero on this platform")
        link = tmp_path / "link.dat"
        link.symlink_to(dev)
        with pytest.raises(ValueError, match="not a regular file"):
            read_bytes_gated(link, 1024)

    def test_nofollow_refuses_symlink(self, tmp_path):
        target = tmp_path / "real.dat"
        target.write_bytes(b"via-link")
        link = tmp_path / "link.dat"
        link.symlink_to(target)
        with pytest.raises(OSError):
            read_bytes_gated(link, 1024, follow_symlinks=False)

    def test_grow_recheck_refuses(self, tmp_path, monkeypatch):
        p = tmp_path / "grow.dat"
        p.write_bytes(b"ab")
        real_fstat = os.fstat

        def grow_after_fstat(fd):
            st = real_fstat(fd)
            with p.open("ab") as fh:  # raw-open: fixture grows its own tmp file
                fh.write(b"Z" * 64)
            return st

        monkeypatch.setattr(os, "fstat", grow_after_fstat)
        with pytest.raises(ReadBudgetExceededError, match="grew"):
            read_bytes_gated(p, 4)

    def test_text_flavor_delegates_to_bytes_body(self, tmp_path):
        p = tmp_path / "t.txt"
        p.write_text("payload")
        assert read_text_gated(p, 1024) == read_bytes_gated(
            p, 1024).decode("utf-8")


class TestJsonDelegation:
    """core.json.utils consumes the single promoted body."""

    def test_json_budget_error_subclasses_read_budget_error(self):
        from core.json.utils import JsonBudgetExceededError
        assert issubclass(JsonBudgetExceededError, ReadBudgetExceededError)

    def test_load_json_budget_refusal_shape_unchanged(self, tmp_path):
        from core.json.utils import JsonBudgetExceededError, load_json
        p = tmp_path / "d.json"
        p.write_text('{"k": "' + "v" * 64 + '"}')
        with pytest.raises(JsonBudgetExceededError):
            load_json(p, strict=True, max_bytes=8)

    def test_load_json_reads_through_delegate(self, tmp_path):
        from core.json.utils import load_json
        p = tmp_path / "d.json"
        p.write_text('{"k": 1}')
        assert load_json(p, strict=True) == {"k": 1}


class TestOpenRegularGated:
    """The exposed open half — same gates, caller-owned stream."""

    def test_opens_regular_file_and_reads(self, tmp_path):
        p = tmp_path / "a.bin"
        p.write_bytes(b"payload")
        with open_regular_gated(p) as fh:
            assert fh.read() == b"payload"

    def test_fileno_carries_the_opened_inode(self, tmp_path):
        p = tmp_path / "a.bin"
        p.write_bytes(b"x")
        with open_regular_gated(p) as fh:
            st_fd = os.fstat(fh.fileno())
            st_name = os.stat(p)
            assert (st_fd.st_dev, st_fd.st_ino) == (
                st_name.st_dev, st_name.st_ino)

    def test_held_stream_pins_identity_across_unlink(self, tmp_path):
        p = tmp_path / "a.bin"
        p.write_bytes(b"pinned")
        with open_regular_gated(p) as fh:
            pin = os.fstat(fh.fileno())
            p.unlink()
            (tmp_path / "a.bin").write_bytes(b"swapped")
            st_now = os.stat(p)
            # Held fd keeps the ORIGINAL inode alive and distinct.
            assert (pin.st_dev, pin.st_ino) != (
                st_now.st_dev, st_now.st_ino)
            fh.seek(0)
            assert fh.read() == b"pinned"

    def test_fifo_refused_without_blocking(self, tmp_path):
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        with pytest.raises(ValueError, match="not a regular file"):
            open_regular_gated(fifo)

    def test_directory_refused(self, tmp_path):
        # Opening a directory O_RDONLY succeeds on POSIX; the fstat
        # regularity gate must still refuse it.
        with pytest.raises((ValueError, OSError)):
            open_regular_gated(tmp_path)

    def test_missing_file_raises_oserror(self, tmp_path):
        with pytest.raises(OSError):
            open_regular_gated(tmp_path / "absent")

    def test_default_follows_symlink(self, tmp_path):
        target = tmp_path / "real.txt"
        target.write_bytes(b"through-link")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        with open_regular_gated(link) as fh:
            assert fh.read() == b"through-link"

    def test_nofollow_refuses_symlink(self, tmp_path):
        target = tmp_path / "real.txt"
        target.write_bytes(b"secret")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        with pytest.raises(OSError):
            open_regular_gated(link, follow_symlinks=False)

    def test_nofollow_opens_plain_regular_file(self, tmp_path):
        p = tmp_path / "plain.txt"
        p.write_bytes(b"ok")
        with open_regular_gated(p, follow_symlinks=False) as fh:
            assert fh.read() == b"ok"

    def test_refusal_leaks_no_fd(self, tmp_path):
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        with pytest.raises(ValueError):
            open_regular_gated(fifo)
        # The fd the refusal opened must be closed: the very next
        # open should land on the lowest free fd, and closing it
        # again via a fresh open proves no descriptor was orphaned.
        probe = tmp_path / "probe.txt"
        probe.write_bytes(b"p")
        fd1 = os.open(probe, os.O_RDONLY)
        os.close(fd1)
        with pytest.raises(ValueError):
            open_regular_gated(fifo)
        fd2 = os.open(probe, os.O_RDONLY)
        os.close(fd2)
        assert fd2 == fd1

    def test_returned_stream_is_binary(self, tmp_path):
        p = tmp_path / "a.bin"
        p.write_bytes(b"\x00\xff")
        with open_regular_gated(p) as fh:
            assert fh.read() == b"\x00\xff"
            assert fh.mode == "rb"
