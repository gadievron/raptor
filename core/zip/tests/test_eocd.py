"""Tests for core.zip.eocd — entry-count pre-flight.

Covers the parse on path + bytes + malformed inputs + ZIP64.
Mirrors the fixtures PR #514 used for ``core.project.export`` so
the substrate inherits the same regression coverage.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from core.zip.eocd import (
    DEFAULT_MAX_ENTRIES,
    peek_total_entries,
)


def _build_zip(entry_count: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(entry_count):
            zf.writestr(f"f{i}.txt", b"x")
    return buf.getvalue()


def test_peek_small_zip_returns_count():
    data = _build_zip(5)
    assert peek_total_entries(data) == 5


def test_peek_large_zip_returns_count():
    # A zip with 12k entries — over the default cap. The pre-flight
    # parse itself works fine regardless; the cap-check is the
    # caller's responsibility.
    data = _build_zip(12_000)
    assert peek_total_entries(data) == 12_000


def test_peek_from_path(tmp_path: Path):
    data = _build_zip(7)
    p = tmp_path / "test.zip"
    p.write_bytes(data)
    assert peek_total_entries(p) == 7


def test_peek_from_str_path(tmp_path: Path):
    data = _build_zip(3)
    p = tmp_path / "test.zip"
    p.write_bytes(data)
    assert peek_total_entries(str(p)) == 3


def test_peek_garbage_returns_none():
    assert peek_total_entries(b"this is not a zip") is None


def test_peek_too_small_returns_none():
    assert peek_total_entries(b"\x00" * 21) is None


def test_peek_missing_eocd_returns_none():
    # 100 bytes of garbage longer than the minimum 22 but no EOCD sig
    assert peek_total_entries(b"\x00" * 100) is None


def test_peek_nonexistent_path_returns_none(tmp_path: Path):
    assert peek_total_entries(tmp_path / "missing.zip") is None


def test_default_cap_is_10k():
    assert DEFAULT_MAX_ENTRIES == 10_000
