"""Tests for ``core.oci.blob`` — streaming layer extraction."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import tarfile
from typing import Dict

import pytest

from core.tar import TarOpenError

from core.oci.blob import (
    DEFAULT_MAX_ENTRY_BYTES,
    UnsupportedLayerMediaType,
    extract_files_from_layer,
)
from core.oci.client import OciRegistryClient, RegistryError
from core.oci.image_ref import parse_image_ref


class _StubResponse:
    def __init__(self, status_code: int, body: bytes,
                 headers: dict | None = None):
        self.status_code = status_code
        self.content = body
        self.text = body.decode("utf-8", errors="replace")
        self.headers = headers or {}

    def iter_content(self, chunk_size: int = 65536):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        pass


class _StubHttp:
    def __init__(self, responses: dict):
        self._responses = responses
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kwargs):
        self.calls.append({"method": method, "url": url,
                           "headers": kwargs.get("headers")})
        if url not in self._responses:
            return _StubResponse(404, b'{"errors": []}')
        return self._responses[url]


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


def test_invalid_gzip_refuses():
    """A blob that isn't actually gzipped tar (corruption, unexpected
    media-type) now REFUSES with TarOpenError instead of returning an
    empty dict a caller would treat as "no findings" success. The
    per-layer consumers (sca dockerfile_from / image_binary_extract)
    guard each layer and skip it — corrupt input no longer masquerades
    as a clean scan result at this seam."""
    with pytest.raises(TarOpenError):
        extract_files_from_layer(
            iter([b"this is not a gzipped tar"]),
            {"var/lib/dpkg/status"},
        )


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


# ---------------------------------------------------------------------------
# Digest verification — extracted content is never returned from an
# unverified stream prefix
# ---------------------------------------------------------------------------


def _make_gzipped_tar_entries(entries) -> bytes:
    """Like ``_make_gzipped_tar`` but takes (name, bytes) pairs so
    duplicate entry names can be encoded (a dict can't hold them)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, content in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return gzip.compress(raw.getvalue())


class _SentinelUnverified(Exception):
    """Raised by the stub stream when it is exhausted — stands in for
    stream_blob's end-of-stream digest check."""


def _verifying_stream(blob: bytes, *, chunk_size: int = 1024):
    """Mimics ``OciRegistryClient.stream_blob``: yields chunks, then
    performs a verification step that only runs when the caller
    consumes the iterator to EOF."""
    for i in range(0, len(blob), chunk_size):
        yield blob[i:i + chunk_size]
    raise _SentinelUnverified("digest mismatch")


def test_early_exit_does_not_skip_source_verification():
    """The wanted file appears early, followed by filler the walk
    can early-exit past. The end-of-stream check (a digest mismatch
    in production) must still fire — content from an unverified
    stream prefix must never be returned."""
    # Incompressible filler: compressible padding would collapse to a
    # handful of chunks that the tar reader's own buffering consumes,
    # masking the early-exit skip this test guards against.
    blob = _make_gzipped_tar({
        "var/lib/dpkg/status": b"Package: foo\n",
        "filler/a": os.urandom(300_000),
        "filler/b": os.urandom(300_000),
    })
    with pytest.raises(_SentinelUnverified):
        extract_files_from_layer(
            _verifying_stream(blob), {"var/lib/dpkg/status"},
        )


def test_stream_blob_digest_mismatch_refuses_extracted_content():
    """End-to-end with the real client: a blob whose bytes do not
    hash to the requested digest must raise instead of handing the
    SBOM path unverified file content."""
    blob = _make_gzipped_tar({
        "var/lib/dpkg/status": b"Package: foo\n",
        "filler/a": os.urandom(300_000),
        "filler/b": os.urandom(300_000),
    })
    lying = "sha256:" + "c" * 64
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    url = f"https://ghcr.io/v2/acme/app/blobs/{lying}"
    client = OciRegistryClient(_StubHttp({url: _StubResponse(200, blob)}))
    with pytest.raises(RegistryError, match="digest mismatch"):
        extract_files_from_layer(
            client.stream_blob(ref, lying), {"var/lib/dpkg/status"},
        )


def test_stream_blob_matching_digest_extracts_normally():
    blob = _make_gzipped_tar({"var/lib/dpkg/status": b"Package: foo\n"})
    good = "sha256:" + hashlib.sha256(blob).hexdigest()
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    url = f"https://ghcr.io/v2/acme/app/blobs/{good}"
    client = OciRegistryClient(_StubHttp({url: _StubResponse(200, blob)}))
    out = extract_files_from_layer(
        client.stream_blob(ref, good), {"var/lib/dpkg/status"},
    )
    assert out == {"var/lib/dpkg/status": b"Package: foo\n"}


def test_duplicate_wanted_entry_refused():
    """A layer carrying the same wanted path twice is hostile: the
    early-exit walk kept the FIRST occurrence while overlay-fs
    runtime semantics apply the LAST. Refuse instead of silently
    scanning the copy the runtime never sees."""
    blob = _make_gzipped_tar_entries([
        ("var/lib/dpkg/status", b"Package: benign-decoy\n"),
        ("var/lib/dpkg/status", b"Package: actually-installed\n"),
    ])
    with pytest.raises(ValueError, match="duplicate"):
        extract_files_from_layer(_stream(blob), {"var/lib/dpkg/status"})


# ---------------------------------------------------------------------------
# Layer mediaType dispatch
# ---------------------------------------------------------------------------


def _make_plain_tar(files: Dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return raw.getvalue()


@pytest.mark.parametrize("media_type", [
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
])
def test_gzip_media_types_extract(media_type):
    blob = _make_gzipped_tar({"var/lib/dpkg/status": b"x"})
    out = extract_files_from_layer(
        _stream(blob), {"var/lib/dpkg/status"}, media_type=media_type,
    )
    assert out == {"var/lib/dpkg/status": b"x"}


@pytest.mark.parametrize("media_type", [
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar",
])
def test_uncompressed_media_types_extract(media_type):
    """A valid uncompressed layer must yield its files — pre-fix the
    hardcoded gzip mode failed to open it and the caller saw an
    empty (falsely clean) result."""
    blob = _make_plain_tar({"var/lib/dpkg/status": b"x"})
    out = extract_files_from_layer(
        _stream(blob), {"var/lib/dpkg/status"}, media_type=media_type,
    )
    assert out == {"var/lib/dpkg/status": b"x"}


@pytest.mark.parametrize("media_type", [
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.oci.image.layer.v1.squashfs",
    "application/octet-stream",
])
def test_unsupported_media_types_raise_loudly(media_type):
    """zstd (valid per OCI spec, undecodable here) and unknown media
    types must raise instead of silently dropping the layer."""
    blob = _make_gzipped_tar({"var/lib/dpkg/status": b"x"})
    with pytest.raises(UnsupportedLayerMediaType):
        extract_files_from_layer(
            _stream(blob), {"var/lib/dpkg/status"}, media_type=media_type,
        )


def test_empty_media_type_defaults_to_gzip():
    blob = _make_gzipped_tar({"var/lib/dpkg/status": b"x"})
    out = extract_files_from_layer(
        _stream(blob), {"var/lib/dpkg/status"}, media_type="",
    )
    assert out == {"var/lib/dpkg/status": b"x"}
