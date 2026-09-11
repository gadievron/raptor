"""Zip extraction with consumer-supplied member selection.

Several raptor consumers walk attacker-influenced zip archives:

  * ``packages/sca/llm/version_diff_review`` — PyPI / RubyGems /
    Cargo / npm source archives in zip form (some PyPI sdists
    ship as ``.zip`` rather than ``.tar.gz``). Reads from in-
    memory ``bytes``, selects by file extension allowlist.

  * ``packages/sca/python_modules`` — PyPI wheel inspection
    (looking for ``*.dist-info/top_level.txt`` to learn what
    module name a distribution installs as). Targeted single-
    file read; doesn't fit the streaming-walk shape and stays
    direct.

  * ``packages/codeql/database_manager`` — extract a CodeQL
    database archive into a destination directory.

  * Future SCA wheel-platform scanner — open wheels and
    inspect ``*.dist-info/METADATA`` + ``WHEEL`` tags.

These share the shape — open archive, iterate members, filter
(safety + caller predicate), bound the read, normalise the path,
stash bytes in a dict — exactly the same shape
:mod:`core.tar.extract_files_from_tar` consolidated for tar.
This module mirrors it for zip.

What's parameterised:

  * ``source`` — accepts either a ``bytes`` blob or a path-like
    object (zipfile requires a seekable backend, so streaming
    chunk-iterators are not supported the way they are for tar).
  * ``selector`` — consumer callback returning the dict key for
    members to keep, or ``None`` to skip.
  * ``max_member_bytes`` — per-member size cap.
  * ``max_ratio`` — per-member compression-ratio cap (zip-
    specific bomb defense).
  * ``allow_absolute_paths`` — passed through to
    :func:`safe_member_reason`.
  * ``expected_count`` — short-circuit when reached.

Returns ``Dict[str, bytes]`` — consumers decode if they want
text. Decoding policy stays with the consumer.
"""

from __future__ import annotations

import io
import logging
import os
import zipfile
from collections.abc import Callable

from .eocd import DEFAULT_MAX_ENTRIES, bomb_shaped_reason, peek_eocd
from .safe_member import (
    DEFAULT_MAX_MEMBER_BYTES,
    DEFAULT_MAX_RATIO,
    safe_member_reason,
)

logger = logging.getLogger(__name__)


class ZipOpenError(zipfile.BadZipFile):
    """Raised when the source is not a readable zip archive (corrupt,
    truncated, or wrong format). Subclasses ``zipfile.BadZipFile`` so
    callers that already guard whole-archive failures keep working;
    the alternative — returning an empty dict — silently converted
    corrupt attacker-influenced input into a "successfully empty"
    result downstream consumers treated as complete (mirrors
    :class:`core.tar.TarOpenError`)."""


class ZipEntryCountExceeded(Exception):
    """Raised when a zip's EOCD pre-flight flags a bomb shape — the
    declared entry count exceeds ``max_entry_count``, or the declared
    central-directory size fails the :func:`core.zip.eocd.
    bomb_shaped_reason` cross-check against that count.

    Always raised (mirrors :class:`core.tar.TarEntryCountExceeded`) —
    a silently-empty return for an over-cap archive is indistinguishable
    from a genuinely empty one, which downstream consumers treated as a
    complete extraction. Consumers that want a domain-specific error
    (project import, CodeQL DB unpack) catch and translate.
    """


class ZipTotalBytesExceeded(Exception):
    """Raised when the CUMULATIVE extracted-bytes total exceeds the caller's
    ``max_total_bytes``.

    The per-member size and entry-count caps bound each member and the count,
    but NOT the aggregate — N members each just under ``max_member_bytes``
    still sum to N×64 MiB in memory. ``max_total_bytes`` (opt-in) bounds the
    sum and ALWAYS raises (never truncates), so a caller extracting to disk
    can't be handed a silently-incomplete result.
    """


def extract_files_from_zip(
    source: bytes | str | os.PathLike | io.IOBase,
    *,
    selector: Callable[[zipfile.ZipInfo], str | None],
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    max_ratio: int = DEFAULT_MAX_RATIO,
    max_entry_count: int = DEFAULT_MAX_ENTRIES,
    allow_absolute_paths: bool = False,
    expected_count: int | None = None,
    max_total_bytes: int | None = None,
    on_skipped: Callable[[zipfile.ZipInfo, str], None] | None = None,
) -> dict[str, bytes]:
    """Walk ``source`` (a zip archive) and return selected members
    as a ``{key: bytes}`` dict.

    ``selector(info)`` returns the dict key for members to keep,
    or ``None`` to skip. Members are first checked by
    :func:`safe_member_reason` — entries that fail safety are
    skipped before the selector even sees them.

    Zip requires a seekable backend, so ``source`` is either a
    ``bytes`` blob, a filesystem path, or a seekable file-like
    object. Streaming iterators (tar's "chunk-iterator" shape)
    aren't supported — zip's central directory lives at the end
    of the archive, so you can't usefully parse one without
    seeking. Consumers that have a stream should buffer it first.

    ``allow_absolute_paths`` defaults to ``False`` (strict on-
    disk extraction default). Read-into-memory consumers
    inspecting absolute-path-bearing archives can pass ``True``.

    ``expected_count`` short-circuits the walk once the result
    dict reaches that size. For consumers that know exactly how
    many files they're after, this avoids reading the rest of a
    multi-hundred-MB archive.

    ``max_entry_count`` defends against zip-bomb-shaped archives
    with millions of entries that would blow up
    ``zipfile.ZipFile.__init__``'s central-directory read. When
    ``source`` is a path or bytes blob (i.e. the EOCD record can
    be located), we read it BEFORE opening the archive and reject
    over-cap declarations early. Defence-in-depth: we also stop
    iterating if the in-memory ``infolist()`` exceeds the cap.
    Default ``DEFAULT_MAX_ENTRIES`` (10 000) is generous for every
    real consumer; set to a very large number to disable.

    FAIL CLOSED: an unreadable archive raises :class:`ZipOpenError`
    and an over-cap / bomb-shaped one raises
    :class:`ZipEntryCountExceeded` — never an empty "success" dict,
    which downstream consumers cannot distinguish from a genuinely
    empty selection (mirrors the :mod:`core.tar` twin). The same
    applies PER MEMBER: an intact central directory over corrupt
    member data (CRC mismatch, mid-file truncation) raises
    :class:`ZipOpenError` instead of silently omitting the member —
    otherwise the whole-archive refusal is bypassable with a crafted
    intact-CD archive (the tar twin refuses the same class via its
    mid-stream ReadError).

    ``on_skipped``: when provided, called as ``on_skipped(info,
    reason)`` for each member the SAFETY filter rejects (oversize,
    traversal, compression bomb, ...) and for encrypted members
    (``reason == "encrypted"`` — the one read-failure shape that
    degrades rather than refuses: encryption is declared metadata,
    not corruption). Without it those skips are debug logs only —
    invisible to callers whose summaries must count them. Exceptions
    it raises abort the walk and propagate (mirrors the tar twin).
    """
    found: dict[str, bytes] = {}

    # Pre-flight: EOCD scan rejects bomb-shaped archives BEFORE
    # ``ZipFile.__init__`` materialises the central directory into
    # RSS. The declared entry count is cross-checked against the
    # declared central-directory size (``bomb_shaped_reason``) — a
    # forged small count in front of a huge real CD would otherwise
    # bypass a count-only gate, since ``ZipFile`` parses the CD until
    # the cd-size buffer is exhausted, ignoring the count. Only
    # attempts the peek when ``source`` is a path or bytes; file-like
    # streams can't be peeked without consuming them (the caller can
    # buffer + re-pass if they want the gate).
    if isinstance(source, (bytes, bytearray, str, os.PathLike)):
        summary = peek_eocd(source)
        reason = (
            bomb_shaped_reason(summary, max_entries=max_entry_count)
            if summary is not None else None
        )
        if reason is not None:
            raise ZipEntryCountExceeded(reason)

    fileobj = _normalise_source(source)
    try:
        zf = zipfile.ZipFile(fileobj)
    except (zipfile.BadZipFile, OSError) as e:
        # ``BadZipFile`` covers malformed central directory and
        # missing end-of-central-directory record. ``OSError``
        # covers truncated streams that surface from the underlying
        # IO rather than zipfile itself. FAIL CLOSED: a corrupt
        # archive must surface as an error, not as a successfully-
        # empty result.
        raise ZipOpenError(f"not a readable zip archive: {e}") from e

    try:
        total_bytes = 0
        for i, info in enumerate(zf.infolist()):
            # In-memory cap. EOCD pre-flight catches the common bomb
            # case but some archives (unusual but valid) have a
            # parseable infolist without a parseable EOCD; this loop
            # bound enforces the cap defensively. The cost saved by
            # short-circuiting here is downstream work, not memory
            # (ZipFile already materialised filelist on open).
            if i >= max_entry_count:
                msg = (
                    f"zip has more than {max_entry_count} entries — "
                    f"refusing as bomb-shape"
                )
                raise ZipEntryCountExceeded(msg)
            if info.is_dir():
                continue
            reason = safe_member_reason(
                info,
                max_size=max_member_bytes,
                max_ratio=max_ratio,
                allow_absolute_paths=allow_absolute_paths,
            )
            if reason.value != "safe":
                logger.debug(
                    "core.zip.extract: skipping unsafe entry %s (%s)",
                    info.filename, reason.value,
                )
                if on_skipped is not None:
                    on_skipped(info, reason.value)
                continue
            key = selector(info)
            if key is None:
                continue
            try:
                # ``open`` returns a ZipExtFile that respects the
                # member's compressed-data bounds — we don't have
                # to defend against over-read separately.
                with zf.open(info) as f:
                    data = f.read()
            except RuntimeError as e:
                # Password-protected entry (no ``pwd`` supplied).
                # Declared metadata, not corruption — degrade by
                # skipping, but surface the skip so caller summaries
                # can count it instead of reporting a clean success.
                logger.debug(
                    "core.zip.extract: skipping encrypted entry %s (%s)",
                    info.filename, e,
                )
                if on_skipped is not None:
                    on_skipped(info, "encrypted")
                continue
            except (zipfile.BadZipFile, OSError) as e:
                # Per-member CRC / structure failure or truncated
                # data behind an INTACT central directory. FAIL
                # CLOSED: silently omitting the member converts a
                # corrupt attacker-influenced archive into a
                # "successfully partial/empty" result — the exact
                # bypass of the whole-archive refusal above (the tar
                # twin raises mid-stream ReadError for this class).
                raise ZipOpenError(
                    f"corrupt member {info.filename!r}: {e}",
                ) from e
            # Aggregate-size cap: bound the SUM of materialised bytes, not just
            # per-member/count. Always raises (never silently truncates).
            if max_total_bytes is not None:
                total_bytes += len(data)
                if total_bytes > max_total_bytes:
                    msg_0 = (
                        f"zip extraction exceeds {max_total_bytes} bytes "
                        f"(bomb-shape); refusing"
                    )
                    raise ZipTotalBytesExceeded(msg_0)
            found[key] = data
            if expected_count is not None and len(found) >= expected_count:
                break
    finally:
        zf.close()
    return found


def _normalise_source(
    source: bytes | str | os.PathLike | io.IOBase,
) -> io.IOBase | str | os.PathLike:
    """Coerce ``source`` into a form ``zipfile.ZipFile`` accepts.

    Bytes are wrapped in :class:`io.BytesIO` (zipfile needs
    something with ``seek``/``read``; raw bytes don't). Paths
    and file-like objects pass through.
    """
    if isinstance(source, (bytes, bytearray)):
        return io.BytesIO(bytes(source))
    return source


__all__ = [
    "ZipEntryCountExceeded",
    "ZipOpenError",
    "ZipTotalBytesExceeded",
    "extract_files_from_zip",
]
