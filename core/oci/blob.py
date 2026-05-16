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
from typing import Dict, Iterable, Set

from core.tar import extract_files_from_tar

logger = logging.getLogger(__name__)


# A sane upper bound on per-file extraction. Real package-state
# files are KBs (apk) to a few MB (dpkg status on a fat distro).
# 64 MB is generous; anything larger is malicious or pointless.
DEFAULT_MAX_ENTRY_BYTES = 64 * 1024 * 1024


def extract_files_from_layer(
    layer_chunks: Iterable[bytes],
    wanted_paths: Set[str],
    *,
    max_entry_bytes: int = DEFAULT_MAX_ENTRY_BYTES,
) -> Dict[str, bytes]:
    """Pull specific files out of a streamed layer blob.

    ``layer_chunks`` is the raw gzipped-tar byte stream (from
    :meth:`OciRegistryClient.stream_blob`).
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
    """
    if not wanted_paths:
        return {}

    normalised_wanted = {_normalise_tar_path(p) for p in wanted_paths}

    def _select(member) -> str | None:
        name = _normalise_tar_path(member.name)
        return name if name in normalised_wanted else None

    return extract_files_from_tar(
        layer_chunks,
        selector=_select,
        mode="r|gz",
        max_member_bytes=max_entry_bytes,
        # Layer member names are legitimately absolute; we read
        # into memory rather than extract to disk, so escape doesn't
        # apply.
        allow_absolute_paths=True,
        # Early-exit once we've found everything — saves streaming
        # through the rest of the layer.
        expected_count=len(normalised_wanted),
    )


def _normalise_tar_path(p: str) -> str:
    """Remove leading ``./`` and ``/`` so the same logical path
    matches across builders that emit different shapes."""
    while p.startswith("./"):
        p = p[2:]
    while p.startswith("/"):
        p = p[1:]
    return p


__all__ = [
    "DEFAULT_MAX_ENTRY_BYTES",
    "extract_files_from_layer",
]
