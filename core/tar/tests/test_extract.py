"""Tests for :func:`core.tar.extract_files_from_tar`.

Covers the substrate that consumers (core.oci.blob, SCA's
version_diff_review) sit on top of — selection, safety filter,
streaming-vs-buffered source, early-exit, mode handling.
"""

from __future__ import annotations

import gzip
import io
import tarfile
from typing import List, Optional

from core.tar.extract import extract_files_from_tar


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tar(
    members: List[tuple],
    *,
    gzipped: bool = False,
) -> bytes:
    """Build an in-memory tar from ``[(name, content_bytes), ...]``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, content in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    raw = buf.getvalue()
    if gzipped:
        raw = gzip.compress(raw)
    return raw


def _chunks(data: bytes, size: int = 4096):
    """Yield ``data`` in chunks — simulates an HTTP body iterator."""
    for i in range(0, len(data), size):
        yield data[i:i + size]


def _select_all(_member) -> str:
    """Selector that keeps every safe member, keyed by member.name."""
    return _member.name


def _select_by_extensions(*exts: str):
    """Selector factory that keeps members whose name ends with one
    of ``exts`` (matches SCA's selection shape)."""
    def _s(member: tarfile.TarInfo) -> Optional[str]:
        for e in exts:
            if member.name.endswith(e):
                return member.name
        return None
    return _s


# ---------------------------------------------------------------------------
# Source shapes — bytes and chunk iterators
# ---------------------------------------------------------------------------


def test_bytes_source_extracts_selected_member():
    raw = _make_tar([("a.txt", b"alpha"), ("b.txt", b"beta")])
    out = extract_files_from_tar(
        raw, selector=_select_all, mode="r:*",
    )
    assert out == {"a.txt": b"alpha", "b.txt": b"beta"}


def test_chunk_source_extracts_selected_member():
    """Streaming iterator must work with stream-mode tar reader."""
    raw = _make_tar([("a.txt", b"alpha")], gzipped=True)
    out = extract_files_from_tar(
        _chunks(raw, size=64), selector=_select_all, mode="r|gz",
    )
    assert out == {"a.txt": b"alpha"}


def test_chunk_source_small_chunks_still_works():
    """Stream reader must reassemble across many tiny chunks."""
    raw = _make_tar(
        [("file.txt", b"hello world this is a longer payload")],
        gzipped=True,
    )
    out = extract_files_from_tar(
        _chunks(raw, size=3), selector=_select_all, mode="r|gz",
    )
    assert out == {"file.txt": b"hello world this is a longer payload"}


# ---------------------------------------------------------------------------
# Selector behaviour
# ---------------------------------------------------------------------------


def test_selector_returning_none_skips_member():
    raw = _make_tar([
        ("keep.txt", b"yes"),
        ("skip.bin", b"no"),
        ("also-keep.txt", b"sure"),
    ])
    out = extract_files_from_tar(
        raw,
        selector=_select_by_extensions(".txt"),
        mode="r:*",
    )
    assert out == {"keep.txt": b"yes", "also-keep.txt": b"sure"}


def test_selector_can_remap_keys():
    """Selector return value becomes the dict key — consumer can
    normalise paths or strip top-level dirs in one go."""
    raw = _make_tar([
        ("pkg-1.0/setup.py", b"setup-content"),
        ("pkg-1.0/README.md", b"readme-content"),
    ])

    def _strip_top(member):
        parts = member.name.split("/", 1)
        return parts[1] if len(parts) > 1 else member.name

    out = extract_files_from_tar(
        raw, selector=_strip_top, mode="r:*",
    )
    assert out == {"setup.py": b"setup-content",
                   "README.md": b"readme-content"}


# ---------------------------------------------------------------------------
# Safety filter
# ---------------------------------------------------------------------------


def test_path_traversal_member_skipped():
    """A `../escape` entry must be rejected by the safety filter
    BEFORE the selector sees it. Selector sees only safe members."""
    raw = _make_tar([
        ("safe.txt", b"safe"),
        ("../escape.txt", b"bad"),
    ])
    seen_by_selector = []

    def _s(member):
        seen_by_selector.append(member.name)
        return member.name

    out = extract_files_from_tar(raw, selector=_s, mode="r:*")
    assert "safe.txt" in out
    assert "../escape.txt" not in out
    assert "../escape.txt" not in seen_by_selector


def test_oversized_member_skipped():
    """A member larger than max_member_bytes is dropped."""
    raw = _make_tar([("big.bin", b"x" * 5000)])
    out = extract_files_from_tar(
        raw,
        selector=_select_all,
        mode="r:*",
        max_member_bytes=1000,
    )
    assert out == {}


def test_absolute_path_strict_default_rejects():
    """Default ``allow_absolute_paths=False`` rejects absolute paths
    — appropriate for consumers that extract to disk."""
    raw = _make_tar([("/etc/passwd", b"not on my watch")])
    out = extract_files_from_tar(
        raw, selector=_select_all, mode="r:*",
    )
    assert out == {}


def test_absolute_path_allowed_when_opted_in():
    """``allow_absolute_paths=True`` lets layer-style absolute names
    through — appropriate for read-into-memory consumers (OCI
    layers carry ``/var/lib/...`` member names)."""
    raw = _make_tar([("/var/lib/dpkg/status", b"package data")])
    out = extract_files_from_tar(
        raw,
        selector=_select_all,
        mode="r:*",
        allow_absolute_paths=True,
    )
    assert out == {"/var/lib/dpkg/status": b"package data"}


# ---------------------------------------------------------------------------
# Early exit
# ---------------------------------------------------------------------------


def test_expected_count_short_circuits():
    """Once expected_count members are found, the walk stops — the
    selector must not be called on any subsequent members."""
    raw = _make_tar([
        ("a.txt", b"first"),
        ("b.txt", b"second"),
        ("c.txt", b"third"),
        ("d.txt", b"fourth"),
    ])

    seen = []

    def _s(member):
        seen.append(member.name)
        return member.name

    out = extract_files_from_tar(
        raw, selector=_s, mode="r:*", expected_count=2,
    )
    assert len(out) == 2
    assert "a.txt" in out and "b.txt" in out
    # The walk MUST have stopped once 2 were collected — c.txt
    # may or may not have been seen by the selector depending on
    # iteration order, but d.txt definitely shouldn't have been.
    # In practice (a, b, c, d order) the walk stops after b.
    assert "d.txt" not in seen


def test_expected_count_none_walks_full_archive():
    """No expected_count → walk every member."""
    raw = _make_tar([
        ("a", b"1"), ("b", b"2"), ("c", b"3"), ("d", b"4"),
    ])
    out = extract_files_from_tar(
        raw, selector=_select_all, mode="r:*",
    )
    assert len(out) == 4


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_directory_member_skipped():
    """Directory entries don't have content — must be skipped
    silently, not crash."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        d = tarfile.TarInfo(name="adir/")
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
        f = tarfile.TarInfo(name="adir/inside.txt")
        f.size = 4
        tf.addfile(f, io.BytesIO(b"data"))
    out = extract_files_from_tar(
        buf.getvalue(), selector=_select_all, mode="r:*",
    )
    assert out == {"adir/inside.txt": b"data"}


def test_invalid_archive_returns_empty():
    """Garbage bytes → empty dict, no crash. Consumers can decide
    whether to log/warn — we just don't blow up."""
    out = extract_files_from_tar(
        b"this is not a tar archive",
        selector=_select_all,
        mode="r:*",
    )
    assert out == {}


def test_invalid_gzip_stream_returns_empty():
    """Truncated / corrupt gzip stream → empty, no crash."""
    out = extract_files_from_tar(
        _chunks(b"\x1f\x8b\x00\x00garbage", size=2),
        selector=_select_all,
        mode="r|gz",
    )
    assert out == {}


def test_empty_archive_returns_empty():
    raw = _make_tar([])
    out = extract_files_from_tar(
        raw, selector=_select_all, mode="r:*",
    )
    assert out == {}


def test_selector_is_only_called_on_files():
    """Directory / symlink / hardlink members must not reach the
    selector — they're filtered out before."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        d = tarfile.TarInfo(name="adir/")
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
        f = tarfile.TarInfo(name="afile.txt")
        f.size = 5
        tf.addfile(f, io.BytesIO(b"hello"))

    seen = []

    def _s(member):
        seen.append((member.name, member.isfile()))
        return member.name

    extract_files_from_tar(
        buf.getvalue(), selector=_s, mode="r:*",
    )
    assert seen == [("afile.txt", True)]
