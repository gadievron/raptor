"""Newline escaping in every Scala query that JSON-embeds CPG text.

Flow/callsite records are emitted as ONE ``MARKER:{json}`` line per
record; a ``.code`` (or name) field containing a literal newline
splits that line mid-string and the Python side logs "failed to parse
flow: Unterminated string" and DROPS the record — observed live in
waves on a target whose code elements span multiple lines. Any field
escaped for the JSON string context must therefore also flatten
carriage returns and newlines.
"""

from __future__ import annotations

import re
from pathlib import Path

_QUERIES_DIR = Path(__file__).resolve().parents[1] / "queries"
_RUNNER = Path(__file__).resolve().parents[1] / "runner.py"

# A Scala JSON-string escape chain (backslash + quote) that does not
# also handle \n on the same expression is a line-splitting hazard.
_QUOTE_ESCAPE = re.compile(r'\.replace\("\\\\", "\\\\\\\\"\)\.replace\("\\"", "\\\\\\""\)')
_NEWLINE_ESCAPE = re.compile(r'\.replace\("\\n", " "\)')


def _offending_lines(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        if _QUOTE_ESCAPE.search(line) and not _NEWLINE_ESCAPE.search(line):
            out.append(line.strip()[:120])
    return out


def test_query_files_escape_newlines_wherever_they_escape_quotes():
    offenders: dict[str, list[str]] = {}
    for sc in sorted(_QUERIES_DIR.glob("*.sc")):
        bad = _offending_lines(sc.read_text())
        if bad:
            offenders[sc.name] = bad
    assert not offenders, offenders


def test_runner_inline_templates_escape_newlines():
    bad = _offending_lines(_RUNNER.read_text())
    assert not bad, bad
