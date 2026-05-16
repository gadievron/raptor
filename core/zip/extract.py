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
from typing import Callable, Dict, Optional, Union

from .eocd import DEFAULT_MAX_ENTRIES, peek_total_entries
from .safe_member import (
    DEFAULT_MAX_MEMBER_BYTES,
    DEFAULT_MAX_RATIO,
    safe_member_reason,
)

logger = logging.getLogger(__name__)


class ZipEntryCountExceeded(Exception):
    """Raised when a zip's declared entry count exceeds ``max_entry_count``.

    Surfaces from :func:`extract_files_from_zip` when the caller opts
    into a hard failure on bomb-shaped archives (default behaviour is
    graceful — return ``{}``). Consumers that want to surface the
    rejection to the operator (e.g. :mod:`core.project.export`) catch
    this and translate to their domain-specific error type.
    """


def extract_files_from_zip(
    source: Union[bytes, str, os.PathLike, io.IOBase],
    *,
    selector: Callable[[zipfile.ZipInfo], Optional[str]],
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    max_ratio: int = DEFAULT_MAX_RATIO,
    max_entry_count: int = DEFAULT_MAX_ENTRIES,
    allow_absolute_paths: bool = False,
    expected_count: Optional[int] = None,
    raise_on_entry_count: bool = False,
) -> Dict[str, bytes]:
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

    ``raise_on_entry_count``: by default an over-cap archive is
    treated as "couldn't read" — returns ``{}`` like any other
    parse failure. Consumers that want to surface the rejection
    explicitly (project import, CodeQL DB unpack) pass ``True``
    to get :class:`ZipEntryCountExceeded`.
    """
    found: Dict[str, bytes] = {}

    # Pre-flight: EOCD scan rejects bomb-shaped archives BEFORE
    # ``ZipFile.__init__`` materialises the central directory into
    # RSS. Only attempts the peek when ``source`` is a path or
    # bytes; file-like streams can't be peeked without consuming
    # them (the caller can buffer + re-pass if they want the gate).
    if isinstance(source, (bytes, bytearray, str, os.PathLike)):
        declared = peek_total_entries(source)
        if declared is not None and declared > max_entry_count:
            msg = (
                f"zip declares {declared} entries in EOCD — exceeds cap "
                f"of {max_entry_count}; refusing as bomb-shape"
            )
            if raise_on_entry_count:
                raise ZipEntryCountExceeded(msg)
            logger.debug("core.zip.extract: %s", msg)
            return found

    fileobj = _normalise_source(source)
    try:
        zf = zipfile.ZipFile(fileobj)
    except (zipfile.BadZipFile, OSError) as e:
        # ``BadZipFile`` covers malformed central directory and
        # missing end-of-central-directory record. ``OSError``
        # covers truncated streams that surface from the underlying
        # IO rather than zipfile itself.
        logger.debug(
            "core.zip.extract: not a valid zip archive (%s); skipping",
            e,
        )
        return found

    try:
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
                if raise_on_entry_count:
                    raise ZipEntryCountExceeded(msg)
                logger.debug("core.zip.extract: %s", msg)
                break
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
                continue
            key = selector(info)
            if key is None:
                continue
            try:
                # ``open`` returns a ZipExtFile that respects the
                # member's compressed-data bounds — we don't have
                # to defend against over-read separately.
                with zf.open(info) as f:
                    found[key] = f.read()
            except (zipfile.BadZipFile, OSError, RuntimeError) as e:
                # ``RuntimeError`` covers password-protected entries
                # in older Python versions; ``BadZipFile`` covers
                # per-member CRC / structure failures that didn't
                # surface during the central-directory parse.
                logger.debug(
                    "core.zip.extract: failed to read %s (%s); skipping",
                    info.filename, e,
                )
                continue
            if expected_count is not None and len(found) >= expected_count:
                break
    finally:
        zf.close()
    return found


def _normalise_source(
    source: Union[bytes, str, os.PathLike, io.IOBase],
) -> Union[io.IOBase, str, os.PathLike]:
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
    "extract_files_from_zip",
]
