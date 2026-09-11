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
import zlib

from core.tar import TarOpenError, extract_files_from_tar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

logger = logging.getLogger(__name__)


# A sane upper bound on per-file extraction. Real package-state
# files are KBs (apk) to a few MB (dpkg status on a fat distro).
# 64 MB is generous; anything larger is malicious or pointless.
DEFAULT_MAX_ENTRY_BYTES = 64 * 1024 * 1024

# Aggregate caps for untrusted registry layers.  The entry-count
# cap mirrors the tar extractor's own default.
DEFAULT_MAX_ENTRY_COUNT = 50_000

# ---------------------------------------------------------------------------
# Decompression budget — READ THIS BEFORE CHANGING ANY OF THE THREE
# CONSTANTS BELOW. This limit has flip-flopped; both failure modes
# have bitten in production:
#
#   * Unbounded (before fa7449b67): a hostile registry could serve a
#     kilobyte-sized gzip blob that stream-decompresses to hundreds of
#     GB. The walk selects only a handful of paths, but stream-mode
#     tarfile must DECOMPRESS every member's data to skip past it and
#     the digest check requires draining to EOF — so "selective"
#     extraction still pays full decompression CPU. gzip tops out
#     near 1030:1, so the exposure is real (42.zip-class DoS).
#   * Flat 256 MiB (fa7449b67 → the ratio budget below): refused
#     PLAINLY LEGITIMATE base-image layers and silently degraded
#     package inventories to partial. Measured on the exact layers a
#     stress sweep refused: python:3.8 211 MB → 597 MB (2.83x),
#     mysql:8 132 MB → 548 MB (4.14x), rust:alpine3.16 216 MB →
#     667 MB (3.09x). Ordinary distro layers routinely decompress to
#     1-2 GB; no flat cap can both admit them and stop bombs.
#
# A bomb is a RATIO, not a size. The budget scales with the
# compressed bytes actually fetched (which upstream already bounds:
# dockerfile_from skips layers over its max_layer_bytes and
# stream_blob enforces its own stream budget):
#
#   budget = min(CEILING, max(FLOOR, RATIO * compressed_size))
#
#   * RATIO 12: three times the worst legitimate ratio measured
#     above (4.14x); real gzip bombs run 100-1030x. Lowering this
#     back toward ~4 will re-refuse legitimate layers; raising it
#     multiplies the CPU a hostile blob can burn per fetched byte.
#   * FLOOR 256 MiB: small layers may decompress this far regardless
#     of ratio (sparse/text layers legitimately hit high ratios at
#     small absolute size; 256 MiB of gunzip is ~1 s of CPU, not a
#     DoS). This is exactly the old flat cap, demoted to the
#     small-input allowance.
#   * CEILING 8 GiB: absolute work bound no observed legitimate
#     layer approaches; keeps worst-case CPU bounded even for
#     callers with large compressed-size caps.
#
# The regression tests (test_blob_budget.py) pin both directions:
# legit-shape large layers accepted, bomb-shape ratios refused.
# ---------------------------------------------------------------------------
DECOMPRESSION_RATIO_BOUND = 12
DECOMPRESSION_BUDGET_FLOOR = 256 * 1024 * 1024
DECOMPRESSION_BUDGET_CEILING = 8 * 1024 * 1024 * 1024


def layer_decompression_budget(compressed_size: int | None) -> int:
    """Aggregate decompressed-bytes budget for one layer extraction.

    ``compressed_size`` is the layer's transferred size (manifest
    descriptor ``size``); ``None`` / non-positive values (absent or
    lying manifests) get the floor — refusing to scale a budget off
    unverified zero keeps a hostile manifest from picking its own
    bound in either direction.
    """
    if not compressed_size or compressed_size <= 0:
        return DECOMPRESSION_BUDGET_FLOOR
    return min(
        DECOMPRESSION_BUDGET_CEILING,
        max(
            DECOMPRESSION_BUDGET_FLOOR,
            DECOMPRESSION_RATIO_BOUND * compressed_size,
        ),
    )


class UnsupportedLayerMediaType(ValueError):
    """Raised for a layer whose ``mediaType`` names a compression
    this module cannot decode (e.g. ``+zstd``) or that isn't a tar
    layer at all. Loud by design: silently skipping a valid-but-
    undecodable layer yields a partial package inventory that is
    indistinguishable from a clean one — an image author could pick
    zstd layers specifically to evade scanning."""


class WantedEntryRefused(ValueError):
    """Raised when a WANTED path exists in the layer but the safety
    filter refused it (oversize, unsafe member shape). Loud for the
    same reason as :class:`UnsupportedLayerMediaType`: an image whose
    dpkg status file is inflated past ``max_entry_bytes`` would
    otherwise produce a falsely-clean, complete-looking inventory —
    exactly the silent-partial evasion this module refuses for media
    types. Non-wanted refused entries stay debug-level skips."""


class DecompressionBudgetExceeded(ValueError):
    """Raised when a gzip layer's decompressed output outruns the
    ratio budget computed from the bytes ACTUALLY fetched. See the
    rationale block on the budget constants above."""


def _gunzip_ratio_guarded(
    chunks: Iterable[bytes],
    *,
    ratio: int | None = None,
    floor: int | None = None,
    ceiling: int | None = None,
) -> Iterator[bytes]:
    """Incrementally gunzip ``chunks`` with an output budget that
    scales with the compressed bytes ACTUALLY fetched so far.

    The declared-size budget (``layer_decompression_budget``) trusts
    the manifest descriptor: a manifest that DECLARES a large layer
    but serves a kilobytes-sized bomb buys ``RATIO * declared`` of
    decompression CPU (up to the ceiling) for almost no transfer.
    Enforcing the ratio against fetched bytes as they stream removes
    that amplification — a lying descriptor cannot raise the budget
    beyond what the served bytes themselves justify. Trade-off,
    documented both ways: this is stricter than the declared-size
    budget for layers whose highly-compressible content FRONT-loads
    the stream (a >3 GiB run of zeros before ~256 MiB of compressed
    input now refuses mid-stream); a bomb is a ratio, and that shape
    is the bomb shape. Raising the floor admits bigger such runs but
    hands every hostile blob that much free CPU.

    Raises :class:`DecompressionBudgetExceeded` on budget breach and
    :class:`core.tar.TarOpenError` on corrupt gzip framing (matching
    what ``tarfile.open(mode="r|gz")`` surfaced before this wrapper
    took over decompression).
    """
    # Module-attribute lookup at CALL time (not def-time defaults) so
    # the budget constants stay one knob, monkeypatchable in tests.
    ratio = DECOMPRESSION_RATIO_BOUND if ratio is None else ratio
    floor = DECOMPRESSION_BUDGET_FLOOR if floor is None else floor
    ceiling = DECOMPRESSION_BUDGET_CEILING if ceiling is None else ceiling
    decomp = zlib.decompressobj(31)  # 31 = gzip container framing
    fetched = 0
    produced = 0
    step = 1 << 20  # bound each decompress call's output allocation

    def _check_budget() -> None:
        budget = min(ceiling, max(floor, ratio * fetched))
        if produced > budget:
            raise DecompressionBudgetExceeded(
                f"layer decompression exceeds the fetched-bytes budget "
                f"({produced} produced from {fetched} fetched; "
                f"ratio bound {ratio}, floor {floor}) — bomb-shape; "
                f"refusing"
            )

    for chunk in chunks:
        fetched += len(chunk)
        data = bytes(chunk)
        while data:
            try:
                out = decomp.decompress(data, step)
            except zlib.error as exc:
                raise TarOpenError(
                    f"corrupt gzip layer stream: {exc}") from exc
            if out:
                produced += len(out)
                _check_budget()
                yield out
            if decomp.eof:
                # Concatenated gzip members (pigz-style multi-stream
                # layers). Trailing NUL padding is not a new member.
                data = decomp.unused_data
                if not data.strip(b"\x00"):
                    return
                decomp = zlib.decompressobj(31)
                continue
            data = decomp.unconsumed_tail
    try:
        out = decomp.flush()
    except zlib.error as exc:
        raise TarOpenError(f"corrupt gzip layer stream: {exc}") from exc
    if out:
        produced += len(out)
        _check_budget()
        yield out


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
    compressed_size: int | None = None,
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

    ``compressed_size`` (the manifest descriptor's ``size`` for this
    layer) scales the aggregate decompression budget — the
    ratio-shaped bomb test documented on the module constants.
    ``None`` applies the floor budget.

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

    def _refuse_wanted_skip(member, reason: str) -> None:
        # Failures channel for the safety filter: a WANTED path that
        # exists but is refused (e.g. oversize dpkg status) must be
        # loud — a silent skip yields the falsely-clean inventory
        # documented on WantedEntryRefused. Unwanted refused entries
        # keep the extractor's debug-level skip.
        name = _normalise_tar_path(member.name)
        if name in normalised_wanted:
            raise WantedEntryRefused(
                f"layer entry {member.name!r} matches wanted path "
                f"{name!r} but was refused by the safety filter "
                f"({reason}, declared size {member.size})"
            )

    chunk_iter = iter(layer_chunks)
    if mode == "r|gz":
        # Decompression runs OUTSIDE tarfile so its output budget can
        # scale with the compressed bytes actually fetched — the
        # declared-size budget below stays as the allocation bound
        # for header/metadata accounting inside the extractor.
        tar_source: Iterable[bytes] = _gunzip_ratio_guarded(chunk_iter)
        tar_mode = "r|"
    else:
        tar_source = chunk_iter
        tar_mode = mode
    found = extract_files_from_tar(
        tar_source,
        selector=_select,
        mode=tar_mode,
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
        # Explicit caps for untrusted registry layers. The
        # decompression budget scales with the layer's compressed
        # size (ratio-shaped bomb test — see the rationale block on
        # the constants above); the fetched-bytes guard above is the
        # tighter live bound for gzip layers.
        max_entry_count=DEFAULT_MAX_ENTRY_COUNT,
        max_total_bytes=layer_decompression_budget(compressed_size),
        on_skipped=_refuse_wanted_skip,
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
    "DecompressionBudgetExceeded",
    "UnsupportedLayerMediaType",
    "WantedEntryRefused",
    "extract_files_from_layer",
]
