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

def test_garbage_input_returns_empty_dict():
    """Garbage bytes that aren't a zip should just return ``{}``
    rather than raise — matches the tar-companion contract."""
    result = extract_files_from_zip(b"this is not a zip", selector=lambda i: i.filename)
    assert result == {}


def test_truncated_zip_returns_what_was_recoverable():
    """Truncated end-of-central-directory means zipfile can't open
    the archive at all — same shape as garbage input."""
    data = _make_zip(("a.txt", b"hello", None))
    # Lop off the trailing EOCD bytes
    truncated = data[: max(1, len(data) - 64)]
    result = extract_files_from_zip(truncated, selector=lambda i: i.filename)
    assert result == {}


# ---------------------------------------------------------------------------
# Compression bomb
# ---------------------------------------------------------------------------

def test_entry_count_cap_rejects_in_memory():
    """A 12k-entry zip exceeds the default cap — extract returns empty."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(12_000):
            zf.writestr(f"f{i}.txt", b"x")
    result = extract_files_from_zip(
        buf.getvalue(), selector=lambda i: i.filename,
    )
    assert result == {}


def test_entry_count_cap_rejects_path(tmp_path: Path):
    """Same defence applies when the source is a filesystem path."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(12_000):
            zf.writestr(f"f{i}.txt", b"x")
    p = tmp_path / "bomb.zip"
    p.write_bytes(buf.getvalue())
    result = extract_files_from_zip(str(p), selector=lambda i: i.filename)
    assert result == {}


def test_entry_count_cap_raises_when_requested():
    """``raise_on_entry_count=True`` surfaces the rejection so the
    caller can render a domain-specific error."""
    from core.zip.extract import ZipEntryCountExceeded
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(12_000):
            zf.writestr(f"f{i}.txt", b"x")
    with pytest.raises(ZipEntryCountExceeded):
        extract_files_from_zip(
            buf.getvalue(),
            selector=lambda i: i.filename,
            raise_on_entry_count=True,
        )


def test_entry_count_cap_overridable_per_call():
    """An operator-trusted archive can raise the cap explicitly."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(50):
            zf.writestr(f"f{i}.txt", b"x")
    # With cap=10 we'd expect rejection (50 > 10).
    result = extract_files_from_zip(
        buf.getvalue(),
        selector=lambda i: i.filename,
        max_entry_count=10,
    )
    assert result == {}


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
