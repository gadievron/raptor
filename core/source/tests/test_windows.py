"""Streaming snippets must match the original whole-file line model."""

import io
import os
import random
from itertools import product

import pytest

from core.source import windows
from core.source.lines import split_lines


@pytest.mark.parametrize("chunk_bytes", [1, 2, 3, 17, 65536])
@pytest.mark.parametrize("raw", [
    b"", b"\n", b"\n\n", b"a", b"a\n", b"a\r\nb\r\n",
    b"a\rb\n", b"a\r\r\nb\n", b"a\v\f\x1c\x85\nb",
    "é🙂\x00\nend\u2028\u2029".encode(),
    b"\xf0\x9f\n\xff\xe2\x82", b"\r\n\r\n\r",
])
def test_differential_line_windows(tmp_path, monkeypatch, chunk_bytes, raw):
    monkeypatch.setattr(windows, "_CHUNK_BYTES", chunk_bytes)
    path = tmp_path / "a.c"
    path.write_bytes(raw)
    expected = split_lines(raw.decode("utf-8", errors="replace"))
    for start, end in product((0, 1, 2, 100), repeat=2):
        assert windows.read_line_window_capped(
            path, start, end, max_bytes=len(raw),
        ) == (expected[start:end], False)


def test_random_binary_inputs(tmp_path, monkeypatch):
    rng = random.Random(71)
    path = tmp_path / "a.c"
    for _ in range(200):
        raw = bytes(rng.choice((10, 13, 0, 97, 194, 226, 128, 255))
                    for _ in range(rng.randrange(200)))
        path.write_bytes(raw)
        start, end = rng.randrange(30), rng.randrange(30)
        monkeypatch.setattr(windows, "_CHUNK_BYTES", rng.randrange(1, 30))
        expected = split_lines(raw.decode("utf-8", errors="replace"))[start:end]
        assert windows.read_line_window_capped(
            path, start, end, max_bytes=len(raw),
        ) == (expected, False)


@pytest.mark.parametrize("bounds", [(0, 1), (0, 0), (100, 200)])
def test_oversize_refused_even_after_window(tmp_path, monkeypatch, bounds):
    monkeypatch.setattr(windows, "_CHUNK_BYTES", 3)
    path = tmp_path / "a.c"
    path.write_bytes(b"a\nb\nc\nd\ne\nf\n")
    assert windows.read_line_window_capped(
        path, *bounds, max_bytes=10,
    ) == ([], True)


def test_later_read_failure_discards_window(monkeypatch):
    class FailingStream(io.BytesIO):
        def read(self, size):
            if self.tell():
                raise OSError("read failed after the selected window")
            return super().read(size)

    monkeypatch.setattr(windows, "_CHUNK_BYTES", 4)
    monkeypatch.setattr(windows, "open_regular",
                        lambda *_: FailingStream(b"a\nb\nc\n"))
    assert windows.read_line_window_capped(None, 0, 1, max_bytes=20) is None


def test_never_reads_past_cap_plus_one(monkeypatch):
    reads = []

    class CountedStream(io.BytesIO):
        def read(self, size):
            chunk = super().read(size)
            reads.append(len(chunk))
            return chunk

    monkeypatch.setattr(windows, "_CHUNK_BYTES", 4)
    monkeypatch.setattr(windows, "open_regular",
                        lambda *_: CountedStream(b"x" * 100))
    assert windows.read_line_window_capped(None, 0, 1, max_bytes=10) == ([], True)
    assert sum(reads) == 11


def test_unreadable_path(tmp_path):
    assert windows.read_line_window_capped(
        tmp_path / "missing", 0, 1, max_bytes=100,
    ) is None


def test_final_symlink_refused(tmp_path):
    real = tmp_path / "real.c"
    real.write_bytes(b"a\n")
    link = tmp_path / "link.c"
    link.symlink_to(real)
    assert windows.read_line_window_capped(link, 0, 1, max_bytes=100) is None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFOs")
def test_fifo_refused_without_waiting_for_writer(tmp_path):
    path = tmp_path / "fifo"
    os.mkfifo(path)
    assert windows.read_line_window_capped(path, 0, 1, max_bytes=100) is None


@pytest.mark.parametrize("raw", [b"", b"x"])
def test_zero_cap(tmp_path, raw):
    path = tmp_path / "a.c"
    path.write_bytes(raw)
    assert windows.read_line_window_capped(
        path, 0, 1, max_bytes=0,
    ) == ([], bool(raw))


@pytest.mark.parametrize("chunk_bytes", [512, 8192, 65536])
@pytest.mark.parametrize("bounds", [(250, 260), (990, 1010), (1999, 2003)])
def test_late_window_prefix_and_chunk_boundaries(tmp_path, monkeypatch, chunk_bytes, bounds):
    raw = b"row\r\nutf8:\xc3\xa9\npartial:\xf0\x9f\nseparator:\xe2\x80\xa8\n" * 700
    path = tmp_path / "many-lines.c"
    path.write_bytes(raw)
    monkeypatch.setattr(windows, "_CHUNK_BYTES", chunk_bytes)
    expected = split_lines(raw.decode("utf-8", errors="replace"))
    assert windows.read_line_window_capped(path, *bounds, max_bytes=len(raw)) == (expected[slice(*bounds)], False)


def test_late_selected_window_still_rejects_tail_failure(monkeypatch):
    class FailingStream(io.BytesIO):
        def read(self, size):
            if self.tell():
                raise OSError("tail read failed")
            return super().read(size)

    monkeypatch.setattr(windows, "_CHUNK_BYTES", 10)
    monkeypatch.setattr(windows, "open_regular", lambda *_: FailingStream(b"a\nb\nc\nd\ne\ntail"))
    assert windows.read_line_window_capped(None, 2, 3, max_bytes=30) is None


def test_late_selected_window_still_rejects_oversize_file(tmp_path, monkeypatch):
    path = tmp_path / "late.c"
    path.write_bytes(b"a\nb\nc\nd\ne\ntail")
    monkeypatch.setattr(windows, "_CHUNK_BYTES", 10)
    assert windows.read_line_window_capped(path, 2, 3, max_bytes=12) == ([], True)
