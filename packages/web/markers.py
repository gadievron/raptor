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
#
# ssti's marker is the evaluated arithmetic of the standard probes
# ({{7*7}} -> 49, {{7*'7'}} -> 7777777). On its own it is far too
# false-positive-prone ("49" appears everywhere) — callers MUST pair it
# with a baseline leg (the fuzzer's three-gate oracle vetoes signals
# already present in the baseline; the verification oracle's control
# legs do the same job on replay).
MARKER_RES: dict[str, re.Pattern] = {
    "sqli": re.compile(
        r"(?:sql\s+syntax|mysql.*error|pg_query|"
        r"unterminated\s+string|unclosed\s+quotation|"
        r"quoted\s+string\s+not\s+properly\s+terminated|"
        r"sqlexception|pg::syntaxerror|sqlite3::exception|"
        r"syntax\s+error\s+near|"
        r"ORA-\d{5}|SQLSTATE\[)",
        re.IGNORECASE,
    ),
    "command_injection": re.compile(
        r"^root:[^:]*:\d+:\d+:|/bin/(?:ba)?sh\b|uid=\d+\([^)]+\)|"
        r"volume serial number|windows ip configuration",
        re.IGNORECASE | re.MULTILINE,
    ),
    "path_traversal": re.compile(
        r"^root:x:\d+:\d+:|^(?:daemon|nobody):x:|\[boot loader\]|"
        r"\[operating systems\]|for 16-bit app support|"
        r"\[extensions\].*\[fonts\]",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    ),
    "ssti": re.compile(r"\b(?:49|7777777)\b"),
}


def marker_present(vuln_type: str, text: str) -> bool:
    """True when *text* carries the class marker for *vuln_type*.

    Unknown classes (and xss, whose signal is probe reflection rather
    than a fixed marker) return False — callers handle reflection
    checks themselves.
    """
    return find_marker(vuln_type, text) is not None


def find_marker(vuln_type: str, text: str) -> str | None:
    """The matched marker text for *vuln_type*, or None.

    Same patterns as :func:`marker_present`; returns the match so the
    fuzzer can carry the concrete signal into finding evidence.
    """
    pattern = MARKER_RES.get(vuln_type)
    if pattern is None:
        return None
    matched = pattern.search(text)
    return matched.group(0) if matched else None
