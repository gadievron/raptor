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

Returns ``dict[str, bytes]`` — consumers decode if they want
text. The byte-vs-text concern is the consumer's, not ours.
"""

from __future__ import annotations

import io
import logging
import tarfile
from collections.abc import Callable, Iterable

from .safe_member import DEFAULT_MAX_MEMBER_BYTES, safe_member_reason

logger = logging.getLogger(__name__)


class _ChunkStream(io.RawIOBase):
    """File-like adapter over a chunk iterator.

    ``tarfile`` in stream mode calls ``.read(n)`` repeatedly. We
    accumulate chunks into an internal buffer and serve out of it.
    Standard pattern for piping an HTTP response body into a tar
    reader without intermediate buffering.
    """

    def __init__(self, chunks: Iterable[bytes]) -> None:
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


def _to_fileobj(source: bytes | Iterable[bytes]) -> io.IOBase:
    """Normalise the source into a file-like object."""
    if isinstance(source, (bytes, bytearray)):
        return io.BytesIO(bytes(source))
    return _ChunkStream(source)


class TarOpenError(tarfile.TarError):
    """Raised when the source is not a readable tar archive (corrupt,
    truncated-at-open, or wrong format). Subclasses ``tarfile.TarError``
    so callers that already guard whole-archive failures keep working;
    the alternative — returning an empty dict — silently converted
    corrupt attacker-influenced input into a "successfully empty"
    result downstream consumers treated as complete."""


class TarEntryCountExceeded(Exception):
    """Raised when a tar's member count exceeds ``max_entry_count`` (opt-in).
    Tar has no central directory, so this bounds a million-tiny-entries walk."""


class TarTotalBytesExceeded(Exception):
    """Raised when the cumulative decompressed-bytes total exceeds
    ``max_total_bytes`` (opt-in) — the aggregate-size bomb defense (per-member
    cap doesn't bound the sum). Counts every member's header-declared size,
    kept OR skipped: in stream mode tarfile must decompress a member's data
    even to skip past it, so uncounted skipped members would leave a
    gzip-bomb CPU DoS open. Also counts metadata-record data (GNU
    longname/longlink, pax headers) that CPython's tarfile materialises
    IN MEMORY during header parsing — checked before the allocation, so
    a 65 KB gzip bomb declaring a multi-hundred-MB longname aborts
    instead of ballooning RSS. Always raises, never silently
    truncates."""


# Member types whose DATA CPython's tarfile reads wholesale into
# memory inside ``tf.next()`` while parsing headers (the value never
# surfaces as a returned member, so per-member accounting in the
# iteration loop cannot see it).
_METADATA_MEMBER_TYPES = frozenset({
    tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
    tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
})


def _budgeted_tarinfo(budget: int, consumed: dict[str, int]) -> type:
    """A per-call ``TarInfo`` subclass enforcing ``budget`` on bytes
    tarfile consumes at HEADER-PARSE time.

    ``tarfile`` materialises GNU longname / longlink and pax record
    data in memory inside ``tf.next()`` — including the ``firstmember``
    parse that happens inside ``tarfile.open`` itself, before any
    caller-side wrapping could intervene. ``_proc_member`` runs after
    the 512-byte header is read but BEFORE the record data is read, so
    charging the declared size here (rounded up to whole blocks, plus
    the header block so an unbounded chain of empty metadata records
    is bounded too) aborts before the allocation. ``consumed`` is
    shared with the iteration loop, which charges regular members'
    declared sizes into the same budget.
    """

    class _BudgetedTarInfo(tarfile.TarInfo):
        def _proc_member(self, tarobj):
            if self.type in _METADATA_MEMBER_TYPES:
                consumed["total"] += tarfile.BLOCKSIZE + self._block(
                    max(0, self.size))
                if consumed["total"] > budget:
                    raise TarTotalBytesExceeded(
                        f"tar metadata records exceed {budget} bytes "
                        f"(bomb-shape); refusing")
            return super()._proc_member(tarobj)

    return _BudgetedTarInfo


def extract_files_from_tar(
    source: bytes | Iterable[bytes],
    *,
    selector: Callable[[tarfile.TarInfo], str | None],
    mode: str = "r|gz",
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    allow_absolute_paths: bool = False,
    expected_count: int | None = None,
    unique_keys: bool = False,
    max_total_bytes: int | None = None,
    max_entry_count: int | None = 50_000,
    sink: Callable[[str, bytes], None] | None = None,
) -> dict[str, bytes]:
    """Walk ``source`` (a tar archive) and return selected members
    as a ``{key: bytes}`` dict.

    ``sink``: when provided, each selected member's bytes are handed
    to ``sink(key, data)`` as soon as they are read and are NOT
    retained — the returned dict maps each key to ``b""`` so
    ``expected_count`` / ``unique_keys`` semantics are unchanged.
    For consumers that write members straight to disk this bounds
    peak memory to one member instead of the whole selection.
    Exceptions raised by the sink abort the walk and propagate.

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
    found: dict[str, bytes] = {}

    fileobj = _to_fileobj(source)
    # Shared budget accumulator: header-time metadata-record bytes
    # (charged by the TarInfo subclass, possibly already during
    # ``tarfile.open``'s firstmember parse) + regular members'
    # declared sizes (charged in the loop below).
    consumed = {"total": 0}
    open_kwargs: dict[str, object] = {}
    if max_total_bytes is not None:
        open_kwargs["tarinfo"] = _budgeted_tarinfo(
            max_total_bytes, consumed)
    try:
        tf = tarfile.open(fileobj=fileobj, mode=mode, **open_kwargs)
    except (tarfile.TarError, EOFError, OSError) as e:
        # ``TarError`` covers ReadError + CompressionError + other
        # malformed-archive cases. ``OSError`` covers truncated
        # gzip streams that surface from the underlying decompress
        # rather than tarfile itself. FAIL CLOSED: a corrupt archive
        # must surface as an error, not as a successfully-empty result.
        raise TarOpenError(f"not a readable tar archive: {e}") from e

    try:
        count = 0
        for member in tf:
            count += 1
            if max_entry_count is not None and count > max_entry_count:
                msg = f"tar exceeds {max_entry_count} entries (bomb-shape); refusing"
                raise TarEntryCountExceeded(msg)
            if max_total_bytes is not None:
                # Count the header-declared size of EVERY member —
                # including ones the safety filter or selector will
                # skip — and check the budget before advancing. In
                # stream mode advancing past a member decompresses
                # its full data, so checking here (header read, data
                # not yet consumed) is what bounds the decompression
                # work; counting only kept members would let a
                # gzip-bomb member burn unbounded CPU while being
                # "skipped". Shares the accumulator with the header-
                # time metadata charging (see _budgeted_tarinfo) so
                # one budget bounds everything the stream makes
                # tarfile consume.
                consumed["total"] += member.size
                if consumed["total"] > max_total_bytes:
                    msg = (
                        f"tar decompression exceeds {max_total_bytes} bytes "
                        f"(bomb-shape); refusing"
                    )
                    raise TarTotalBytesExceeded(msg)
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
            if unique_keys and key in found:
                # Strict-mode: refuse a tar that produces the same
                # logical key twice. A malicious tar can populate
                # ``found`` with attacker-chosen content under N
                # distinct selector hits, then the legitimate file
                # later in the stream is never read because
                # ``expected_count`` already short-circuited the
                # walk. Caller opts in when the selector domain
                # guarantees uniqueness (e.g. ``wanted_paths`` is
                # a set of distinct logical paths).
                f.close()
                msg = f"duplicate tar key {key!r} (unique_keys=True)"
                raise ValueError(msg)
            try:
                data = f.read()
            finally:
                f.close()
            if sink is not None:
                sink(key, data)
                del data
                found[key] = b""
            else:
                found[key] = data
            if expected_count is not None and len(found) >= expected_count:
                break
    finally:
        tf.close()
    return found


__all__ = [
    "TarOpenError",
    "extract_files_from_tar",
]
