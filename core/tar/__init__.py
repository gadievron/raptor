"""Tar primitives for attacker-influenced archives.

Two raptor consumers walk tar archives we didn't author:

  * :mod:`core.oci.blob` — layer tarballs from container registries
    (streaming, gzipped, members can legitimately be absolute paths,
    consumer reads-into-memory).
  * ``packages/sca/llm/version_diff_review`` — PyPI / Cargo / npm /
    RubyGems source archives (in-memory blob, mixed compression,
    consumer filters by extension and strips the top-level dir).

Both share two concerns: deciding whether a member is safe to
extract, and walking the archive to pull out the members the
caller wants. This module centralises both:

  * :func:`safe_member_reason` — wraps PEP 706 / Python 3.12+
    :func:`tarfile.data_filter` plus our own pre-checks (size cap,
    hard-link refusal, special-file refusal, optional absolute-path
    refusal). Returns :class:`UnsafeMemberReason` for diagnostic
    logging.
  * :func:`extract_files_from_tar` — generic tar walker that
    applies the safety filter, asks a consumer-supplied selector
    for the dict key (or ``None`` to skip), and returns
    ``{key: bytes}``. Handles streaming-from-iterator vs
    buffered-from-bytes, configurable open mode, optional early-
    exit when an expected member count is reached.

Limitations:

  * Requires Python 3.12+ for :func:`tarfile.data_filter`. Earlier
    versions get a stricter fallback that's slightly over-cautious.
  * Doesn't cover compression-bomb attacks (a 1 KB tar that
    extracts to 100 GB). The per-member size cap defends against
    "one fake package-state file the size of the whole archive";
    cumulative bombs need a wrapping budget the consumer enforces.
  * Decoding stays with the consumer — :func:`extract_files_from_tar`
    always returns bytes. Callers that want text decode themselves.
"""

from .extract import extract_files_from_tar
from .safe_member import (
    DEFAULT_MAX_MEMBER_BYTES,
    UnsafeMemberReason,
    is_safe_member,
    safe_member_reason,
)

__all__ = [
    "DEFAULT_MAX_MEMBER_BYTES",
    "UnsafeMemberReason",
    "extract_files_from_tar",
    "is_safe_member",
    "safe_member_reason",
]
