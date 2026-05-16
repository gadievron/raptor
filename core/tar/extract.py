"""Streaming tar extraction with consumer-supplied member selection.

Two raptor consumers walk attacker-influenced tar archives and pull
selected members into memory:

  * :mod:`core.oci.blob` — layer tarballs from container registries.
    Streams from an HTTP response body. Selects by exact path
    membership in a wanted-paths set (e.g. ``var/lib/dpkg/status``).
    Layer member names are legitimately absolute, and entries are
    read into memory so on-disk traversal isn't a risk.

  * ``packages/sca/llm/version_diff_review`` — PyPI / RubyGems /
    Cargo / npm source archives. Reads from an in-memory ``bytes``
    blob (download is small enough to buffer). Selects by file
    extension allowlist (e.g. ``.py``, ``.js``, ``.md``). Strips the
    top-level directory prefix that source distributions wrap their
    contents in.

The two have the same shape — open archive, iterate members,
filter (safety + caller predicate), bound the read, normalise the
path, stash bytes in a dict — but historically each rolled its
own loop. That meant the safety check, size budget, and
streaming/buffered handling drifted. This module unifies them.

What's parameterised:

  * ``source`` — accepts either a chunk iterator (streaming) or
    a single ``bytes`` blob (buffered). Internally normalises to a
    file-like object the underlying ``tarfile`` reader can drive.
  * ``mode`` — passed through to ``tarfile.open``. Defaults to
    ``"r|gz"`` (streaming gzip, can't seek). SCA uses ``"r:*"``
    (auto-detect compression, supports seeking — needed because
    PyPI sdists can be gzip OR bzip2 OR xz).
  * ``selector`` — consumer callback returning the dict key for
    members to keep, or ``None`` to skip. The split (predicate +
    key generation in one call) lets the caller normalise the path
    however suits.
  * ``max_member_bytes`` — per-member size cap (defends against
    "package state file" the size of the whole archive).
  * ``allow_absolute_paths`` — passed through to
    :func:`safe_member_reason`. ``True`` for read-into-memory
    consumers (no escape risk applies).
  * ``expected_count`` — when set and reached, the iterator
    short-circuits without reading the rest of the archive. Saves
    streaming through hundreds of megabytes after the wanted
    paths have all been found.

Returns ``Dict[str, bytes]`` — consumers decode if they want
text. The byte-vs-text concern is the consumer's, not ours.
"""

from __future__ import annotations

import io
import logging
import tarfile
from typing import Callable, Dict, Iterable, Optional, Union

from .safe_member import DEFAULT_MAX_MEMBER_BYTES, safe_member_reason

logger = logging.getLogger(__name__)


class _ChunkStream(io.RawIOBase):
    """File-like adapter over a chunk iterator.

    ``tarfile`` in stream mode calls ``.read(n)`` repeatedly. We
    accumulate chunks into an internal buffer and serve out of it.
    Standard pattern for piping an HTTP response body into a tar
    reader without intermediate buffering.
    """

    def __init__(self, chunks: Iterable[bytes]):
        self._chunks = iter(chunks)
        self._buf = b""
        self._eof = False

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            while not self._eof:
                self._fill_buffer()
            data, self._buf = self._buf, b""
            return data
        while not self._eof and len(self._buf) < size:
            self._fill_buffer()
        if size <= len(self._buf):
            data, self._buf = self._buf[:size], self._buf[size:]
            return data
        data, self._buf = self._buf, b""
        return data

    def _fill_buffer(self) -> None:
        try:
            chunk = next(self._chunks)
        except StopIteration:
            self._eof = True
            return
        if chunk:
            self._buf += chunk


def _to_fileobj(source: Union[bytes, Iterable[bytes]]) -> io.IOBase:
    """Normalise the source into a file-like object."""
    if isinstance(source, (bytes, bytearray)):
        return io.BytesIO(bytes(source))
    return _ChunkStream(source)


def extract_files_from_tar(
    source: Union[bytes, Iterable[bytes]],
    *,
    selector: Callable[[tarfile.TarInfo], Optional[str]],
    mode: str = "r|gz",
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    allow_absolute_paths: bool = False,
    expected_count: Optional[int] = None,
) -> Dict[str, bytes]:
    """Walk ``source`` (a tar archive) and return selected members
    as a ``{key: bytes}`` dict.

    ``selector(member)`` returns the dict key for members to keep,
    or ``None`` to skip. Members are first checked by
    :func:`safe_member_reason` — entries that fail safety are
    skipped before the selector even sees them.

    ``mode`` is passed straight to :func:`tarfile.open`. Stream
    modes (``"r|gz"``, ``"r|"``, etc.) work member-by-member without
    seeking — required when ``source`` is a chunk iterator. Random-
    access modes (``"r:*"``, ``"r:gz"``) can rewind but consume the
    whole stream into a temp file first.

    ``allow_absolute_paths`` defaults to ``False`` (the strict
    on-disk extraction default). Read-into-memory consumers (OCI
    layer extraction) can pass ``True`` because there's no on-disk
    path to escape from.

    ``expected_count`` short-circuits the walk once the result dict
    reaches that size. For consumers that know exactly how many
    files they're after (targeted extraction), this avoids
    streaming through the rest of a multi-hundred-MB archive.
    """
    found: Dict[str, bytes] = {}

    fileobj = _to_fileobj(source)
    try:
        tf = tarfile.open(fileobj=fileobj, mode=mode)
    except (tarfile.TarError, EOFError, OSError) as e:
        # ``TarError`` covers ReadError + CompressionError + other
        # malformed-archive cases. ``OSError`` covers truncated
        # gzip streams that surface from the underlying decompress
        # rather than tarfile itself.
        logger.debug(
            "core.tar.extract: not a valid tar archive (%s); skipping",
            e,
        )
        return found

    try:
        for member in tf:
            if not member.isfile():
                continue
            reason = safe_member_reason(
                member,
                max_size=max_member_bytes,
                allow_absolute_paths=allow_absolute_paths,
            )
            if reason.value != "safe":
                logger.debug(
                    "core.tar.extract: skipping unsafe entry %s (%s)",
                    member.name, reason.value,
                )
                continue
            key = selector(member)
            if key is None:
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            try:
                found[key] = f.read()
            finally:
                f.close()
            if expected_count is not None and len(found) >= expected_count:
                break
    finally:
        tf.close()
    return found


__all__ = [
    "extract_files_from_tar",
]
