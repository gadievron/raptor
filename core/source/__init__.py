"""Source code text processing utilities.

Two concerns:

- **Comment stripping** (``core.source.strip``) — string-literal-aware
  comment removal for C-family, Python, and shell languages.
- **Line-range slicing** (``core.source.lines``) — 1-indexed, inclusive
  line range operations used throughout RAPTOR.
"""

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
    "number_lines",
    "read_context",
    "read_lines",
    "slice_lines",
    "slice_text",
    "strip_c_comments",
    "strip_comments",
    "strip_python_comments",
    "strip_shell_comments",
]
