"""Response marker detection shared by the fuzzer heuristics and the
verification oracle.

One source of truth for "does this response text carry the class's
vulnerability marker": the fuzzer uses it for the initial heuristic
classification, the oracle re-uses it for replay and control legs so
the two layers can never drift apart on what counts as a hit.
"""

from __future__ import annotations

import re

# Marker regexes per vulnerability class. XSS is deliberately absent:
# its signal is reflection of the probe itself (payload / canary
# containment), not a fixed response pattern.
MARKER_RES: dict[str, re.Pattern] = {
    "sqli": re.compile(
        r"(?:sql\s+syntax|mysql.*error|pg_query|"
        r"unterminated\s+string|unclosed\s+quotation|"
        r"ORA-\d{5}|SQLSTATE\[)",
        re.IGNORECASE,
    ),
    "command_injection": re.compile(
        r"^root:[^:]*:\d+:\d+:|/bin/(?:ba)?sh\b|uid=\d+\(",
        re.MULTILINE,
    ),
    "path_traversal": re.compile(
        r"^root:x:\d+:\d+:|\[boot loader\]|"
        r"\[extensions\].*\[fonts\]",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    ),
}


def marker_present(vuln_type: str, text: str) -> bool:
    """True when *text* carries the class marker for *vuln_type*.

    Unknown classes (and xss, whose signal is probe reflection rather
    than a fixed marker) return False — callers handle reflection
    checks themselves.
    """
    pattern = MARKER_RES.get(vuln_type)
    if pattern is None:
        return False
    return bool(pattern.search(text))
