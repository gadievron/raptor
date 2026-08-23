"""Single-file decompression (gz / bz2 / xz / zst), capped against bombs.

We read at most ``max_bytes + 1`` of *decompressed* output from the stdlib's
lazy decompressing readers, so a bomb (tiny input → enormous output) is never
fully materialised in memory — we stop one byte past the cap and reject.
"""

import bz2
import gzip
import lzma
from pathlib import Path

from .errors import ArchiveError, DecompressionLimitExceeded, UnsupportedArchive

# Cap on decompressed output for a single compressed file (also the budget for
# a compressed-tar's decompressed bytes before tar parsing).
DEFAULT_MAX_DECOMPRESSED_BYTES = 1 << 30  # 1 GiB

_TAR_MAGIC_OFFSET = 257
_TAR_MAGICS = (b"ustar\x0000", b"ustar  \x00", b"ustar")


def _zstd_open(path, mode="rb"):
    # Python 3.14+ ships zstd in the stdlib (PEP 784); fall back to the
    # third-party `zstandard` package on older interpreters.
    try:
        from compression import zstd
        return zstd.open(path, mode)
    except Exception:
        import zstandard
        return zstandard.open(path, mode)


_OPENERS = {
    "gz": gzip.open,
    "bz2": bz2.open,
    "xz": lzma.open,
    "zst": _zstd_open,
}


# Read granularity for the streaming decompressor. Bounded single
# allocations: the retired ``fh.read(max_bytes + 1)`` asked the lazy
# reader for up to 1 GiB + 1 in ONE call, so a bomb (or merely a big
# legitimate stream) was materialised wholesale before the cap check.
_CHUNK_BYTES = 1 << 20


def iter_decompressed(path, fmt: str,
                      max_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES):
    """Yield decompressed chunks of a single-file stream, capped.

    Incremental budget accounting: raises ``DecompressionLimitExceeded``
    as soon as the running decompressed total passes ``max_bytes`` — at
    most one chunk (1 MiB) is ever read beyond the cap, and nothing is
    retained here, so consumers can stream a capped decompression to
    disk without the output ever being resident in memory. Raises
    ``UnsupportedArchive`` for an unknown ``fmt`` and ``ArchiveError``
    for a corrupt/truncated stream (possibly mid-iteration — corruption
    may only surface after valid leading chunks).
    """
    opener = _OPENERS.get(fmt)
    if opener is None:
        msg = f"no single-file decompressor for {fmt!r}"
        raise UnsupportedArchive(msg)
    total = 0
    try:
        with opener(Path(path), "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_BYTES)
                if not chunk:
                    return
                total += len(chunk)
                if total > max_bytes:
                    raise DecompressionLimitExceeded(
                        f"{fmt} stream exceeds {max_bytes} bytes "
                        f"decompressed — refusing as bomb")
                yield chunk
    except (DecompressionLimitExceeded, UnsupportedArchive):
        raise
    except Exception as e:  # malformed/truncated stream, decompress error
        msg = f"{fmt} decompression failed: {e}"
        raise ArchiveError(msg) from e


def decompress_single(path, fmt: str,
                      max_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES) -> bytes:
    """Decompress a single-file ``gz``/``bz2``/``xz``/``zst`` to bytes, capped.

    Buffered convenience wrapper over :func:`iter_decompressed` — same
    cap semantics and error types; the output is held in memory, so
    consumers that only need to relay the bytes (to disk, to a tar
    reader) should iterate the streaming variant instead.
    """
    return b"".join(iter_decompressed(path, fmt, max_bytes=max_bytes))


def looks_like_tar(data: bytes) -> bool:
    """True if ``data`` carries a POSIX tar header (ustar magic at offset 257)."""
    if len(data) <= _TAR_MAGIC_OFFSET:
        return False
    window = data[_TAR_MAGIC_OFFSET:_TAR_MAGIC_OFFSET + 8]
    return any(window.startswith(m) for m in _TAR_MAGICS)
