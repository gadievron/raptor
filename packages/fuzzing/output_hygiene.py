"""Terminal hygiene for untrusted target output.

Text that originates from the fuzzed target or its writable output
directory (instance log tails, ``fuzzer_stats`` values, libFuzzer
stderr lines) is relayed to the operator's terminal by our loggers.
A hostile target can embed ANSI/OSC escape sequences there — title
changes, clipboard writes, screen rewrites that hide or forge report
lines. The logging stack applies no control-character filtering, so
strip at the trust boundary instead.
"""

from __future__ import annotations

import re

# Every C0 control except \n and \t (keep multi-line log tails
# readable), plus DEL and the C1 range: C1 bytes act as CSI/OSC
# introducers on some terminals. Stripping ESC leaves any escape
# sequence as inert printable text ("[31m").
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x80-\x9f]")


def strip_terminal_controls(text: str) -> str:
    """Return *text* with terminal control characters removed."""
    return _CONTROL_CHARS_RE.sub("", text)
