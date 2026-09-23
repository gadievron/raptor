"""Source code text processing utilities.

Two concerns:

- **Comment stripping** (``core.source.strip``) — string-literal-aware
  comment removal for C-family, Python, and shell languages.
- **Line-range slicing** (``core.source.lines``) — 1-indexed, inclusive
  line range operations used throughout RAPTOR.
- **Contained/capped reads** (``core.source.contained``) — containment
  under an analysed root plus size-capped reads, for paths derived
  from untrusted finding records.
"""

from core.source.contained import (
    DEFAULT_MAX_SOURCE_CHARS,
    open_regular,
    read_bytes_capped,
    read_contained,
    read_text_capped,
)
from core.source.lines import (
    number_lines,
    read_context,
    read_lines,
    slice_lines,
    slice_text,
)
from core.source.strip import (
    C_FAMILY_SUFFIXES,
    strip_c_comments,
    strip_comments,
    strip_python_comments,
    strip_shell_comments,
)

__all__ = [
    "C_FAMILY_SUFFIXES",
    "DEFAULT_MAX_SOURCE_CHARS",
    "number_lines",
    "open_regular",
    "read_bytes_capped",
    "read_contained",
    "read_context",
    "read_lines",
    "read_text_capped",
    "slice_lines",
    "slice_text",
    "strip_c_comments",
    "strip_comments",
    "strip_python_comments",
    "strip_shell_comments",
]
