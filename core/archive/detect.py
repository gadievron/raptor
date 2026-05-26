"""Magic-byte detection of archive / single-file-compression formats.

Detection is by content, never by file extension — an attacker-supplied
target can lie about (or omit) its extension, and the whole point of recording
provenance is that we know what we *actually* unpacked.

Returns the OUTER format. A compressed tar (``.tar.gz``) is reported as its
compressor (``gz``); the extractor then probes whether the decompressed bytes
are a tar or a single file.
"""

from pathlib import Path
from typing import Optional

# Formats whose magic sits at offset 0. Order matters only in that more
# specific signatures must precede generic ones (none overlap here).
_MAGIC_AT_0 = (
    ("zip", b"PK\x03\x04"),
    ("zip", b"PK\x05\x06"),   # empty archive
    ("zip", b"PK\x07\x08"),   # spanned/data-descriptor
    ("gz",  b"\x1f\x8b"),
    ("bz2", b"BZh"),
    ("xz",  b"\xfd7zXZ\x00"),
    ("zst", b"\x28\xb5\x2f\xfd"),
)

# POSIX tar carries "ustar" at offset 257 (both GNU and POSIX variants).
_TAR_MAGIC_OFFSET = 257
_TAR_MAGICS = (b"ustar\x0000", b"ustar  \x00", b"ustar")

# Enough to cover the tar magic at offset 257 plus all offset-0 signatures.
_PEEK_BYTES = 512


def detect_format(path) -> Optional[str]:
    """Return ``'zip'|'tar'|'gz'|'bz2'|'xz'|'zst'`` from the file's magic
    bytes, or ``None`` if it is not a recognised archive/compressed file
    (or can't be read). Never raises.
    """
    p = Path(path)
    try:
        with open(p, "rb") as fh:
            head = fh.read(_PEEK_BYTES)
    except OSError:
        return None
    if not head:
        return None

    # Tar first: its magic is deep in the header, and a tar is never also a
    # zip/gz/… at offset 0, so there's no ambiguity.
    if len(head) > _TAR_MAGIC_OFFSET:
        window = head[_TAR_MAGIC_OFFSET:_TAR_MAGIC_OFFSET + 8]
        if any(window.startswith(m) for m in _TAR_MAGICS):
            return "tar"

    for fmt, magic in _MAGIC_AT_0:
        if head.startswith(magic):
            return fmt
    return None


def is_archive(path) -> bool:
    """True if ``path`` is a recognised archive/compressed file."""
    return detect_format(path) is not None
