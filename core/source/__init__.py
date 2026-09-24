"""Source code text processing utilities.

Concerns:

- **Comment stripping** (``core.source.strip``) — string-literal-aware
  comment removal for C-family, Python, and shell languages.
- **Line-range slicing** (``core.source.lines``) — 1-indexed, inclusive
  line range operations used throughout RAPTOR.
- **Contained/capped reads** (``core.source.contained``) — containment
  under an analysed root plus size-capped reads, for paths derived
  from untrusted finding records.
- **Gated reads** (``core.source.gated``) — the raising flavor of the
  same read discipline, for loaders whose file is REQUIRED and whose
  refusal classes must surface distinctly.
- **Anchored opens** (``core.source.beneath``) — dir-fd–anchored opens
  beneath a root, closing the resolve-then-open swap window.
"""

from core.source.beneath import open_regular_beneath
from core.source.contained import (
    DEFAULT_MAX_SOURCE_CHARS,
    open_regular,
    read_bytes_capped,
    read_contained,
    read_text_capped,
)
from core.source.gated import (
    ReadBudgetExceededError,
    read_text_gated,
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
    "ReadBudgetExceededError",
    "number_lines",
    "open_regular",
    "open_regular_beneath",
    "read_bytes_capped",
    "read_contained",
    "read_context",
    "read_lines",
    "read_text_capped",
    "read_text_gated",
    "slice_lines",
    "slice_text",
    "strip_c_comments",
    "strip_comments",
    "strip_python_comments",
    "strip_shell_comments",
]
