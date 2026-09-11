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
    DEFAULT_MAX_CD_BYTES,
    DEFAULT_MAX_ENTRIES,
    EocdSummary,
    bomb_shaped_reason,
    peek_eocd,
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


# ---------------------------------------------------------------------------
# cd-size cross-check (peek_eocd + bomb_shaped_reason)
# ---------------------------------------------------------------------------

def _forge_entry_count(data: bytes, forged_count: int) -> bytes:
    """Patch the EOCD's entries-on-disk + total-entries fields,
    leaving the (real) cd-size untouched — the forged-count bomb
    shape: a count-only pre-flight passes while ``ZipFile()`` still
    materialises the whole real central directory."""
    import struct

    buf = bytearray(data)
    off = buf.rfind(b"\x50\x4b\x05\x06")
    assert off >= 0, "test fixture: EOCD signature not found"
    struct.pack_into("<HH", buf, off + 8, forged_count, forged_count)
    return bytes(buf)


def test_peek_eocd_returns_entries_and_cd_size():
    data = _build_zip(5)
    summary = peek_eocd(data)
    assert summary is not None
    assert summary.entries_total == 5
    # 5 records, 46-byte fixed header + short name each.
    assert 5 * 46 <= summary.cd_size < 5 * 4096


def test_bomb_shaped_reason_accepts_legitimate_archive():
    summary = peek_eocd(_build_zip(200))
    assert bomb_shaped_reason(summary) is None


def test_bomb_shaped_reason_over_entry_cap():
    reason = bomb_shaped_reason(EocdSummary(entries_total=10_001, cd_size=1))
    assert reason is not None
    assert "zip-bomb shape" in reason


def test_forged_small_count_rejected_by_cd_size_cross_check():
    """The R-class bypass: a zip whose real central directory holds
    1 000 records but whose EOCD declares 3 entries. A count-only
    gate passes it; the cd-size cross-check must not."""
    data = _forge_entry_count(_build_zip(1_000), 3)
    summary = peek_eocd(data)
    assert summary is not None
    assert summary.entries_total == 3            # the forged claim
    assert summary.cd_size >= 1_000 * 46         # the real CD
    reason = bomb_shaped_reason(summary)
    assert reason is not None
    assert "central directory" in reason
    assert "zip-bomb shape" in reason


def test_bomb_shaped_reason_absolute_cd_cap():
    # Per-entry bound satisfied (20k entries x 4096 > 65 MiB) but the
    # absolute cap still fires when the caller raises the entry cap.
    summary = EocdSummary(entries_total=20_000, cd_size=65 * 1024 * 1024)
    reason = bomb_shaped_reason(summary, max_entries=50_000)
    assert reason is not None
    assert str(DEFAULT_MAX_CD_BYTES) in reason


def test_extract_rejects_forged_count_zip():
    import pytest

    from core.zip import ZipEntryCountExceeded, extract_files_from_zip

    data = _forge_entry_count(_build_zip(1_000), 3)
    # Fail closed: the bomb-shape refusal is always a typed raise, so
    # a caller can never mistake it for a successfully-empty archive.
    with pytest.raises(ZipEntryCountExceeded, match="zip-bomb shape"):
        extract_files_from_zip(data, selector=lambda n: n)


# ---------------------------------------------------------------------------
# ZIP64 parity with zipfile._EndRecData64 (unconditional locator follow)
# ---------------------------------------------------------------------------

def _append_zip64_records(data: bytes, entries: int, cd_size: int) -> bytes:
    """Rebuild ``data``'s tail with a ZIP64 EOCD record + locator
    inserted BEFORE the classic EOCD (whose fields stay small and
    non-sentinel) — the shape where zipfile uses the ZIP64 numbers
    while a sentinel-gated peek would use the classic ones."""
    import struct

    eocd_off = data.rfind(b"\x50\x4b\x05\x06")
    assert eocd_off >= 0, "test fixture: EOCD signature not found"
    zip64_eocd = (
        b"\x50\x4b\x06\x06"
        + struct.pack("<Q", 44)          # size of remaining record
        + struct.pack("<HH", 45, 45)     # version made by / needed
        + struct.pack("<II", 0, 0)       # disk numbers
        + struct.pack("<QQ", entries, entries)  # entries disk / total
        + struct.pack("<QQ", cd_size, 0)        # cd size / cd offset
    )
    zip64_off = eocd_off  # record lands where the classic EOCD was
    locator = (
        b"\x50\x4b\x06\x07"
        + struct.pack("<I", 0)
        + struct.pack("<Q", zip64_off)
        + struct.pack("<I", 1)
    )
    return data[:eocd_off] + zip64_eocd + locator + data[eocd_off:]


def test_zip64_locator_overrides_non_sentinel_eocd():
    """A ZIP64 record declaring 30k entries behind a classic EOCD
    declaring 5 must be what the gate sees — zipfile follows the
    locator unconditionally, so the pre-flight must too."""
    data = _append_zip64_records(
        _build_zip(5), entries=30_000, cd_size=30_000 * 46)
    summary = peek_eocd(data)
    assert summary is not None
    assert summary.entries_total == 30_000
    assert bomb_shaped_reason(summary) is not None


def test_zip64_locator_absent_uses_classic_fields():
    """No locator: classic EOCD fields are authoritative (unchanged
    behaviour for the entire non-ZIP64 population)."""
    data = _build_zip(5)
    summary = peek_eocd(data)
    assert summary is not None
    assert summary.entries_total == 5


def test_zip64_extract_gate_fires_on_non_sentinel_eocd(tmp_path: Path):
    import pytest

    from core.zip import ZipEntryCountExceeded, extract_files_from_zip

    data = _append_zip64_records(
        _build_zip(5), entries=30_000, cd_size=30_000 * 46)
    with pytest.raises(ZipEntryCountExceeded):
        extract_files_from_zip(data, selector=lambda n: n)
    # Path-backed source takes the fh arm of the ZIP64 follow-up.
    p = tmp_path / "zip64.zip"
    p.write_bytes(data)
    with pytest.raises(ZipEntryCountExceeded):
        extract_files_from_zip(str(p), selector=lambda n: n)
