"""Tests for ``core.oci.blob`` — streaming layer extraction."""

from __future__ import annotations

import gzip
import io
import tarfile
from typing import Dict

from core.oci.blob import (
    DEFAULT_MAX_ENTRY_BYTES,
    extract_files_from_layer,
)


def _make_gzipped_tar(files: Dict[str, bytes]) -> bytes:
    """Build a gzipped tar from a name → bytes mapping. Used as the
    test fixture in lieu of real registry layers."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return gzip.compress(raw.getvalue())


def _stream(blob: bytes, *, chunk_size: int = 1024):
    """Yield the blob in chunks — simulates the registry-stream
    iterator the real client exposes."""
    for i in range(0, len(blob), chunk_size):
        yield blob[i:i + chunk_size]


# ---------------------------------------------------------------------------
# Single-file extraction
# ---------------------------------------------------------------------------


def test_extract_one_wanted_file():
    blob = _make_gzipped_tar({
        "var/lib/dpkg/status": b"Package: foo\nVersion: 1.0\n",
        "etc/passwd": b"root:x:0:0\n",
        "usr/bin/python": b"\x7fELF...",
    })
    out = extract_files_from_layer(
        _stream(blob), {"var/lib/dpkg/status"},
    )
    assert out == {
        "var/lib/dpkg/status": b"Package: foo\nVersion: 1.0\n",
    }


def test_unwanted_files_not_extracted():
    """The point of streaming + early-exit is that non-wanted
    files are read past, not held in memory. Verify the result
    contains only what was asked for."""
    blob = _make_gzipped_tar({
        "var/lib/dpkg/status": b"x",
        "huge/binary": b"\x00" * 10_000,
    })
    out = extract_files_from_layer(_stream(blob), {"var/lib/dpkg/status"})
    assert "huge/binary" not in out


# ---------------------------------------------------------------------------
# Multiple wanted files
# ---------------------------------------------------------------------------


def test_extract_multiple_wanted_files():
    """SBOM extraction wants two or three files at once (depending
    on which package manager is on the layer). All present ones
    come back."""
    blob = _make_gzipped_tar({
        "var/lib/dpkg/status": b"deb-content",
        "lib/apk/db/installed": b"apk-content",
        "var/lib/rpm/rpmdb.sqlite": b"rpm-content",
        "irrelevant/file": b"x",
    })
    out = extract_files_from_layer(_stream(blob), {
        "var/lib/dpkg/status",
        "lib/apk/db/installed",
        "var/lib/rpm/rpmdb.sqlite",
    })
    assert out == {
        "var/lib/dpkg/status": b"deb-content",
        "lib/apk/db/installed": b"apk-content",
        "var/lib/rpm/rpmdb.sqlite": b"rpm-content",
    }


def test_partial_match_when_only_some_present():
    """Layers stack — different layers carry different package-
    manager state. A single layer matching only ONE of the wanted
    paths returns just that one; the consumer stitches across
    layers itself."""
    blob = _make_gzipped_tar({"var/lib/dpkg/status": b"x"})
    out = extract_files_from_layer(_stream(blob), {
        "var/lib/dpkg/status", "lib/apk/db/installed",
    })
    assert out == {"var/lib/dpkg/status": b"x"}


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------


def test_leading_slash_in_archive_normalised_away():
    """Some tar builders emit ``/var/lib/...`` (absolute) while
    others emit ``var/lib/...`` (relative). The wanted-path match
    must handle both."""
    blob = _make_gzipped_tar({"/var/lib/dpkg/status": b"x"})
    out = extract_files_from_layer(_stream(blob), {"var/lib/dpkg/status"})
    assert out == {"var/lib/dpkg/status": b"x"}


def test_leading_dot_slash_normalised():
    """Same for the ``./var/lib/...`` shape (BSD tar default)."""
    blob = _make_gzipped_tar({"./var/lib/dpkg/status": b"x"})
    out = extract_files_from_layer(_stream(blob), {"var/lib/dpkg/status"})
    assert out == {"var/lib/dpkg/status": b"x"}


# ---------------------------------------------------------------------------
# Bounded read budget
# ---------------------------------------------------------------------------


def test_oversized_entry_skipped():
    """A pathological / malicious layer with a 1 GB ``dpkg/status``
    file shouldn't OOM raptor. ``max_entry_bytes`` caps individual
    extracts; oversized entries are skipped silently."""
    blob = _make_gzipped_tar({
        "var/lib/dpkg/status": b"x" * 1024,
    })
    out = extract_files_from_layer(
        _stream(blob), {"var/lib/dpkg/status"},
        max_entry_bytes=10,                     # 10 bytes — file is 1024
    )
    assert out == {}                            # skipped


def test_default_max_entry_bytes_is_generous():
    """Just verify the constant is something operators can hit
    without weird-but-real package-state files."""
    assert DEFAULT_MAX_ENTRY_BYTES >= 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Empty / malformed inputs
# ---------------------------------------------------------------------------


def test_empty_wanted_set_returns_empty():
    """No wanted paths → no work. Caller can skip layers cheaply."""
    blob = _make_gzipped_tar({"x": b"y"})
    assert extract_files_from_layer(_stream(blob), set()) == {}


def test_invalid_gzip_returns_empty():
    """A blob that isn't actually gzipped tar (corruption,
    unexpected media-type) must not crash; the caller treats
    'no findings' as success."""
    out = extract_files_from_layer(
        iter([b"this is not a gzipped tar"]),
        {"var/lib/dpkg/status"},
    )
    assert out == {}


def test_empty_layer():
    """An empty layer (just a tar with no files) is uncommon but
    valid — gracefully returns no findings."""
    blob = _make_gzipped_tar({})
    assert extract_files_from_layer(
        _stream(blob), {"var/lib/dpkg/status"},
    ) == {}


# ---------------------------------------------------------------------------
# Streaming semantics
# ---------------------------------------------------------------------------


def test_streaming_with_small_chunks():
    """Chunk-size doesn't matter for correctness — extraction
    must work even if the registry feeds us 1 byte at a time
    (real iterators sometimes do for keep-alive reasons)."""
    blob = _make_gzipped_tar({"var/lib/dpkg/status": b"abc" * 1000})
    out = extract_files_from_layer(
        _stream(blob, chunk_size=1),
        {"var/lib/dpkg/status"},
    )
    assert out == {"var/lib/dpkg/status": b"abc" * 1000}


def test_directories_skipped():
    """Tar entries that are directories shouldn't trigger an
    extract attempt — caller asked for a file, not a dir."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        info = tarfile.TarInfo(name="var/lib/dpkg")
        info.type = tarfile.DIRTYPE
        info.size = 0
        tf.addfile(info)
        # Then add a real file.
        info2 = tarfile.TarInfo(name="var/lib/dpkg/status")
        body = b"package data"
        info2.size = len(body)
        tf.addfile(info2, io.BytesIO(body))
    blob = gzip.compress(raw.getvalue())
    out = extract_files_from_layer(
        _stream(blob), {"var/lib/dpkg", "var/lib/dpkg/status"},
    )
    # Directory not extracted; file is.
    assert out == {"var/lib/dpkg/status": b"package data"}
