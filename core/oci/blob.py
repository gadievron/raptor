"""Streaming layer-blob inspection.

A layer is a gzipped tar archive (~100 MB compressed common,
several GB rare-but-real). For SBOM extraction we only need a few
specific files (``var/lib/dpkg/status``, ``lib/apk/db/installed``,
``var/lib/rpm/rpmdb.sqlite``). Streaming the gzipped bytes through
a tar reader and pulling just those entries — instead of pulling
the whole blob into memory or to disk — is what makes this
tolerable.

The actual tar walking (open in stream mode, iterate members,
apply the safety filter, stash the bytes) lives in
:func:`core.tar.extract_files_from_tar`. This module supplies the
OCI-specific bits: path normalisation (``./`` and leading ``/``
stripped) and a wanted-paths-set membership selector. Layer
member names are legitimately absolute (``/var/lib/dpkg/status``
appears as ``var/lib/dpkg/status`` after normalisation), and the
consumer reads into memory rather than to disk, so
``allow_absolute_paths=True`` is correct here.
"""

from __future__ import annotations

import logging
import re

from core.tar import extract_files_from_tar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)


# A sane upper bound on per-file extraction. Real package-state
# files are KBs (apk) to a few MB (dpkg status on a fat distro).
# 64 MB is generous; anything larger is malicious or pointless.
DEFAULT_MAX_ENTRY_BYTES = 64 * 1024 * 1024

# Aggregate caps for untrusted registry layers.  The entry-count
# cap mirrors the tar extractor's own default; the total-bytes cap
# bounds the sum of all extracted entries (the per-member cap alone
# doesn't prevent a bomb made of many smaller files).
DEFAULT_MAX_ENTRY_COUNT = 50_000
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024


class UnsupportedLayerMediaType(ValueError):
    """Raised for a layer whose ``mediaType`` names a compression
    this module cannot decode (e.g. ``+zstd``) or that isn't a tar
    layer at all. Loud by design: silently skipping a valid-but-
    undecodable layer yields a partial package inventory that is
    indistinguishable from a clean one — an image author could pick
    zstd layers specifically to evade scanning."""


def _tar_mode_for_media_type(media_type: str) -> str:
    """Map an OCI/Docker layer ``mediaType`` to the ``tarfile`` open
    mode. Gzip and uncompressed tar layers are supported; anything
    else (zstd, unknown) raises :class:`UnsupportedLayerMediaType`.

    An empty ``media_type`` keeps the historical gzip default for
    callers without manifest context.
    """
    mt = (media_type or "").split(";", 1)[0].strip().lower()
    if not mt:
        return "r|gz"
    # OCI: application/vnd.oci.image.layer.v1.tar+gzip
    # Docker: application/vnd.docker.image.rootfs.diff.tar.gzip
    # (plus the *.foreign / nondistributable variants of each).
    if mt.endswith(("+gzip", ".gzip")):
        return "r|gz"
    # Uncompressed: application/vnd.oci.image.layer.v1.tar,
    # application/vnd.docker.image.rootfs.diff.tar.
    if mt.endswith((".tar", "+tar")):
        return "r|"
    raise UnsupportedLayerMediaType(
        f"unsupported layer mediaType {media_type!r}: only gzip and "
        f"uncompressed tar layers can be decoded"
    )


def extract_files_from_layer(
    layer_chunks: Iterable[bytes],
    wanted_paths: set[str],
    *,
    max_entry_bytes: int = DEFAULT_MAX_ENTRY_BYTES,
    media_type: str = "",
) -> dict[str, bytes]:
    """Pull specific files out of a streamed layer blob.

    ``layer_chunks`` is the raw layer byte stream (from
    :meth:`OciRegistryClient.stream_blob`). ``media_type`` is the
    layer descriptor's ``mediaType`` from the image manifest; it
    selects the decompression mode (gzip vs uncompressed tar) and
    unsupported compressions raise
    :class:`UnsupportedLayerMediaType` instead of silently yielding
    an empty (falsely clean) result. When empty, the historical
    gzip default applies.
    ``wanted_paths`` is the set of in-archive paths we care about,
    e.g. ``{"var/lib/dpkg/status", "lib/apk/db/installed"}``. Paths
    are matched against the tar entry name with leading ``./`` and
    leading ``/`` normalised away (different image build pipelines
    emit them differently).

    Returns a dict mapping wanted-path → file content bytes. Paths
    not present in this layer are simply absent from the result —
    the caller stitches together multi-layer state by overlaying
    later layers on earlier ones (later wins, per Docker's
    overlay-fs semantics).

    Skips entries larger than ``max_entry_bytes`` with a debug log
    — defends against pathological / malicious inputs without
    inflating memory.

    Integrity: ``layer_chunks`` typically comes from
    :meth:`OciRegistryClient.stream_blob`, which verifies the blob's
    sha256 only once the stream is consumed to EOF. The early-exit
    walk used to stop as soon as every wanted path had been seen,
    which skipped that verification entirely — extracted content
    was returned from an unauthenticated prefix of the blob. Now the
    remaining stream is always drained to EOF before results are
    returned, so a digest mismatch raises (from the source iterator)
    instead of handing back unverified bytes. The walk also covers
    the whole archive (no early exit) and refuses duplicate wanted
    paths (``unique_keys``): first-occurrence-wins plus early exit
    diverged from tar/overlay last-wins semantics, letting an image
    author show this scanner a benign copy while the runtime saw a
    later, different one.
    """
    mode = _tar_mode_for_media_type(media_type)
    if not wanted_paths:
        return {}

    normalised_wanted = {_normalise_tar_path(p) for p in wanted_paths}

    def _select(member) -> str | None:
        name = _normalise_tar_path(member.name)
        return name if name in normalised_wanted else None

    chunk_iter = iter(layer_chunks)
    found = extract_files_from_tar(
        chunk_iter,
        selector=_select,
        mode=mode,
        max_member_bytes=max_entry_bytes,
        # Layer member names are legitimately absolute; we read
        # into memory rather than extract to disk, so escape doesn't
        # apply.
        allow_absolute_paths=True,
        # No expected_count early exit: the walk must see the whole
        # archive so a duplicated wanted path can't shadow the copy
        # the runtime actually sees, and the source has to be
        # consumed to EOF for digest verification anyway. The
        # max_total_bytes cap below bounds the decompression work.
        unique_keys=True,
        # Explicit caps for untrusted registry layers.
        max_entry_count=DEFAULT_MAX_ENTRY_COUNT,
        max_total_bytes=DEFAULT_MAX_TOTAL_BYTES,
    )
    # Drain the source to EOF before returning anything. stream_blob
    # only performs its sha256 check on exhaustion; returning after
    # an early exit would skip the check by construction, so no
    # extracted content leaves this function until the source
    # iterator has run to completion (raising on digest mismatch).
    for _ in chunk_iter:
        pass
    return found


_LEADING_PREFIX_RE = re.compile(r"^(?:\.?/)+")


def _normalise_tar_path(p: str) -> str:
    """Remove leading ``./`` and ``/`` so the same logical path
    matches across builders that emit different shapes.

    Single regex pass (constant-time amortised) replaces the
    previous two ``while`` loops which were O(n) per leading
    component on attacker-controlled prefixes. A malicious layer
    entry like ``./././...`` repeated 10M times forced 10M string
    slices through the old loops; the regex bounds peak memory
    + CPU regardless of the leading prefix.
    """
    return _LEADING_PREFIX_RE.sub("", p)


__all__ = [
    "DEFAULT_MAX_ENTRY_BYTES",
    "UnsupportedLayerMediaType",
    "extract_files_from_layer",
]
