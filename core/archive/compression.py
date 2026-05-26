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


def decompress_single(path, fmt: str,
                      max_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES) -> bytes:
    """Decompress a single-file ``gz``/``bz2``/``xz``/``zst`` to bytes, capped.

    Raises ``DecompressionLimitExceeded`` if output would exceed ``max_bytes``
    (bomb defense), ``UnsupportedArchive`` for an unknown ``fmt``, and
    ``ArchiveError`` if the stream is corrupt/truncated.
    """
    opener = _OPENERS.get(fmt)
    if opener is None:
        raise UnsupportedArchive(f"no single-file decompressor for {fmt!r}")
    try:
        with opener(Path(path), "rb") as fh:
            data = fh.read(max_bytes + 1)
    except DecompressionLimitExceeded:
        raise
    except Exception as e:  # malformed/truncated stream, decompress error
        raise ArchiveError(f"{fmt} decompression failed: {e}") from e
    if len(data) > max_bytes:
        raise DecompressionLimitExceeded(
            f"{fmt} stream exceeds {max_bytes} bytes decompressed — refusing as bomb"
        )
    return data


def looks_like_tar(data: bytes) -> bool:
    """True if ``data`` carries a POSIX tar header (ustar magic at offset 257)."""
    if len(data) <= _TAR_MAGIC_OFFSET:
        return False
    window = data[_TAR_MAGIC_OFFSET:_TAR_MAGIC_OFFSET + 8]
    return any(window.startswith(m) for m in _TAR_MAGICS)
