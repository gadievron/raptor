"""Tests for core.zip.extract.

Covers the selector callback contract, the path-shape filtering
(via safe_member), expected_count short-circuit, and the source-
type variants (bytes vs file-like).
"""

from __future__ import annotations

import io
import stat
import zipfile
from pathlib import Path

import pytest

from core.zip.extract import extract_files_from_zip


def _make_zip(*entries: tuple[str, bytes, int | None]) -> bytes:
    """Build a zip in memory. See test_safe_member._zip_with."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            zi = zipfile.ZipInfo(name)
            if mode is not None:
                zi.external_attr = mode << 16
            zf.writestr(zi, data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Selector contract
# ---------------------------------------------------------------------------

def test_selector_returning_filename_keeps_member():
    data = _make_zip(("a.txt", b"hello", None))
    result = extract_files_from_zip(data, selector=lambda i: i.filename)
    assert result == {"a.txt": b"hello"}


def test_selector_returning_none_skips_member():
    data = _make_zip(
        ("keep.txt", b"yes", None),
        ("drop.bin", b"no",  None),
    )

    def select(info):
        return info.filename if info.filename.endswith(".txt") else None

    result = extract_files_from_zip(data, selector=select)
    assert result == {"keep.txt": b"yes"}


def test_selector_can_rewrite_key():
    """The dict-key returned by the selector is the dict key
    we use — it doesn't have to match the archive path."""
    data = _make_zip(("project-1.0/src/foo.py", b"x = 1", None))

    def strip_top(info):
        parts = info.filename.split("/", 1)
        return parts[1] if len(parts) > 1 else info.filename

    result = extract_files_from_zip(data, selector=strip_top)
    assert result == {"src/foo.py": b"x = 1"}


# ---------------------------------------------------------------------------
# Safety filter integration
# ---------------------------------------------------------------------------

def test_path_traversal_member_is_skipped():
    data = _make_zip(
        ("safe.txt", b"ok", None),
        ("../escape.txt", b"bad", None),
    )
    result = extract_files_from_zip(data, selector=lambda i: i.filename)
    assert "../escape.txt" not in result
    assert result == {"safe.txt": b"ok"}


def test_absolute_path_skipped_when_not_allowed():
    data = _make_zip(("/etc/passwd", b"bad", None))
    result = extract_files_from_zip(data, selector=lambda i: i.filename)
    assert result == {}


def test_absolute_path_kept_when_allowed():
    data = _make_zip(("/etc/passwd", b"shadow", None))
    result = extract_files_from_zip(
        data, selector=lambda i: i.filename, allow_absolute_paths=True,
    )
    assert result == {"/etc/passwd": b"shadow"}


def test_symlink_member_skipped():
    data = _make_zip(("link", b"target", stat.S_IFLNK | 0o777))
    result = extract_files_from_zip(data, selector=lambda i: i.filename)
    assert result == {}


# ---------------------------------------------------------------------------
# Source-type variants
# ---------------------------------------------------------------------------

def test_extract_from_bytes_blob():
    data = _make_zip(("a.txt", b"hello", None))
    result = extract_files_from_zip(data, selector=lambda i: i.filename)
    assert result == {"a.txt": b"hello"}


def test_extract_from_filesystem_path(tmp_path: Path):
    data = _make_zip(("a.txt", b"hello", None))
    archive = tmp_path / "test.zip"
    archive.write_bytes(data)
    result = extract_files_from_zip(
        str(archive), selector=lambda i: i.filename,
    )
    assert result == {"a.txt": b"hello"}


def test_extract_from_file_like():
    data = _make_zip(("a.txt", b"hello", None))
    result = extract_files_from_zip(
        io.BytesIO(data), selector=lambda i: i.filename,
    )
    assert result == {"a.txt": b"hello"}


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

def test_expected_count_short_circuit():
    """Once expected_count members have been collected, the walk
    stops without reading the rest."""
    data = _make_zip(
        ("a.txt", b"a", None),
        ("b.txt", b"b", None),
        ("c.txt", b"c", None),
    )
    result = extract_files_from_zip(
        data, selector=lambda i: i.filename, expected_count=2,
    )
    assert len(result) == 2


def test_directory_entries_skipped():
    """zipfile may emit explicit directory entries — they shouldn't
    surface in the result."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # ZipInfo with trailing slash represents a directory
        zi = zipfile.ZipInfo("subdir/")
        zi.external_attr = (stat.S_IFDIR | 0o755) << 16
        zf.writestr(zi, b"")
        zf.writestr("subdir/file.txt", b"hello")

    result = extract_files_from_zip(buf.getvalue(), selector=lambda i: i.filename)
    assert result == {"subdir/file.txt": b"hello"}


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------

def test_garbage_input_raises_zip_open_error():
    """Garbage bytes that aren't a zip FAIL CLOSED with a typed error
    — matches the tar-companion contract (TarOpenError): an empty
    "success" dict is indistinguishable from a genuinely empty
    selection downstream."""
    from core.zip.extract import ZipOpenError
    with pytest.raises(ZipOpenError):
        extract_files_from_zip(
            b"this is not a zip", selector=lambda i: i.filename)


def test_zip_open_error_is_badzipfile():
    """Callers already guarding ``zipfile.BadZipFile`` keep working."""
    from core.zip.extract import ZipOpenError
    with pytest.raises(zipfile.BadZipFile):
        extract_files_from_zip(
            b"this is not a zip", selector=lambda i: i.filename)
    assert issubclass(ZipOpenError, zipfile.BadZipFile)


def test_truncated_zip_raises_zip_open_error():
    """Truncated end-of-central-directory means zipfile can't open
    the archive at all — same fail-closed shape as garbage input."""
    from core.zip.extract import ZipOpenError
    data = _make_zip(("a.txt", b"hello", None))
    # Lop off the trailing EOCD bytes
    truncated = data[: max(1, len(data) - 64)]
    with pytest.raises(ZipOpenError):
        extract_files_from_zip(truncated, selector=lambda i: i.filename)


def test_valid_empty_zip_still_returns_empty_dict():
    """Fail-closed is for UNREADABLE archives only: a well-formed zip
    with no selected members legitimately returns ``{}``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED):
        pass
    result = extract_files_from_zip(
        buf.getvalue(), selector=lambda i: i.filename)
    assert result == {}


# ---------------------------------------------------------------------------
# Compression bomb
# ---------------------------------------------------------------------------

def test_entry_count_cap_raises_in_memory():
    """A 12k-entry zip exceeds the default cap — typed refusal."""
    from core.zip.extract import ZipEntryCountExceeded
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(12_000):
            zf.writestr(f"f{i}.txt", b"x")
    with pytest.raises(ZipEntryCountExceeded):
        extract_files_from_zip(
            buf.getvalue(), selector=lambda i: i.filename,
        )


def test_entry_count_cap_raises_path(tmp_path: Path):
    """Same defence applies when the source is a filesystem path."""
    from core.zip.extract import ZipEntryCountExceeded
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(12_000):
            zf.writestr(f"f{i}.txt", b"x")
    p = tmp_path / "bomb.zip"
    p.write_bytes(buf.getvalue())
    with pytest.raises(ZipEntryCountExceeded):
        extract_files_from_zip(str(p), selector=lambda i: i.filename)


def test_entry_count_cap_tightenable_per_call():
    """A per-call lower cap fires the same typed refusal (50 > 10)."""
    from core.zip.extract import ZipEntryCountExceeded
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(50):
            zf.writestr(f"f{i}.txt", b"x")
    with pytest.raises(ZipEntryCountExceeded):
        extract_files_from_zip(
            buf.getvalue(),
            selector=lambda i: i.filename,
            max_entry_count=10,
        )


def test_entry_count_cap_raisable_per_call():
    """An operator-trusted archive can raise the cap explicitly and
    extract normally (the fail-closed refusal is cap-relative, not
    absolute)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(50):
            zf.writestr(f"f{i}.txt", b"x")
    result = extract_files_from_zip(
        buf.getvalue(),
        selector=lambda i: i.filename,
        max_entry_count=100,
    )
    assert len(result) == 50


def test_compression_bomb_skipped():
    """A high-ratio member doesn't make it into the result dict."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("bomb.bin", b"\x00" * (10 * 1024 * 1024))
        zf.writestr("ok.txt", b"hello")
    result = extract_files_from_zip(
        buf.getvalue(), selector=lambda i: i.filename,
    )
    assert "bomb.bin" not in result
    assert result == {"ok.txt": b"hello"}


def test_max_total_bytes_caps_aggregate_and_default_unchanged():
    from core.zip.extract import ZipTotalBytesExceeded
    z = _make_zip(*[(f"f{i}", b"A" * 100, None) for i in range(5)])
    # Default (no cap): all members extracted — existing callers unaffected.
    assert len(extract_files_from_zip(z, selector=lambda i: i.filename)) == 5
    # A cap below the aggregate raises (never silently truncates).
    with pytest.raises(ZipTotalBytesExceeded):
        extract_files_from_zip(
            z, selector=lambda i: i.filename, max_total_bytes=250)


# ---------------------------------------------------------------------------
# Per-member fail-closed (intact CD, corrupt member data) + encrypted degrade
# ---------------------------------------------------------------------------

def _corrupt_member_zip() -> bytes:
    """Intact central directory, member data corrupted (CRC mismatch)."""
    data = bytearray(_make_zip(
        ("a.txt", b"A" * 100, None),
        ("b.txt", b"B" * 10, None),
    ))
    i = data.find(b"A" * 100)
    assert i > 0, "fixture: stored member data not found"
    data[i:i + 4] = b"XXXX"
    return bytes(data)


def _encrypted_member_zip() -> bytes:
    """Two members; enc.txt's central-directory flag bits declare
    encryption (stdlib can't WRITE encrypted zips, so patch the flag)."""
    raw = bytearray(_make_zip(
        ("enc.txt", b"secret", None),
        ("ok.txt", b"fine", None),
    ))
    pos = 0
    while True:
        pos = raw.find(b"PK\x01\x02", pos)
        if pos < 0:
            break
        name_len = int.from_bytes(raw[pos + 28:pos + 30], "little")
        if bytes(raw[pos + 46:pos + 46 + name_len]) == b"enc.txt":
            raw[pos + 8] |= 0x01
        pos += 4
    return bytes(raw)


def test_corrupt_member_data_raises_zip_open_error():
    """An archive whose CD is intact but whose member DATA is corrupt
    (CRC mismatch) must refuse — silently omitting the member was a
    bypass of the whole-archive fail-closed contract (a crafted
    intact-CD zip extracted to a 0-file "success")."""
    from core.zip.extract import ZipOpenError
    with pytest.raises(ZipOpenError, match="corrupt member"):
        extract_files_from_zip(
            _corrupt_member_zip(), selector=lambda i: i.filename)


def test_encrypted_member_degrades_and_is_reported():
    """Encryption is declared metadata, not corruption: the member is
    skipped, the rest extracts, and on_skipped surfaces the skip."""
    skips: list[tuple[str, str]] = []
    result = extract_files_from_zip(
        _encrypted_member_zip(),
        selector=lambda i: i.filename,
        on_skipped=lambda info, reason: skips.append(
            (info.filename, reason)),
    )
    assert result == {"ok.txt": b"fine"}
    assert skips == [("enc.txt", "encrypted")]


def test_on_skipped_reports_safety_filter_rejects():
    data = _make_zip(
        ("../escape.txt", b"bad", None),
        ("safe.txt", b"ok", None),
    )
    skips: list[tuple[str, str]] = []
    result = extract_files_from_zip(
        data, selector=lambda i: i.filename,
        on_skipped=lambda info, reason: skips.append(
            (info.filename, reason)),
    )
    assert result == {"safe.txt": b"ok"}
    assert ("../escape.txt", "path_traversal") in skips
