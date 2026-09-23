"""YAML-walk extraction of GitHub Actions ``uses:`` references.

The ``uses:`` consumers (``supply_chain.gha_drift`` and the
``parsers.inline_installs`` workflow parser) historically matched a
per-line regex.  That covers the plain scalar shape
(``uses: owner/repo@ref``) but GitHub's YAML parser also runs block
scalars (``uses: >-\\n  owner/repo@ref``), flow mappings
(``- {uses: owner/repo@ref}``), quoted keys (``"uses": ...``) and
anchor/alias indirection — all of which the regex misses, so an
attacker-chosen serialization silently removed a compromised-action
reference from the whole gha_* lane (drift, freshness, sunset, OSV
matching and the GHA+SENTINEL composite pair).

This module walks the parsed YAML document and collects every string
value of a ``uses`` mapping key, at any depth (workflow job steps,
job-level reusable-workflow references, composite-action
``runs.steps``).  Callers UNION the walk's specs with their regex
pass: the regex keeps exact line numbers for the plain shapes, the
walk catches the evasion shapes, and a parse failure degrades to
regex-only (never worse than the historical behaviour).
"""

from __future__ import annotations

import logging

from ._yaml_fast import safe_load
from core.source.lines import split_lines

logger = logging.getLogger(__name__)


def extract_uses_specs(text: str) -> list[str] | None:
    """Parse ``text`` as YAML and return every ``uses:`` string value.

    Returns ``None`` when the document does not parse (callers fall
    back to their regex extraction) and ``[]`` when it parses but
    contains no ``uses`` keys.  Duplicate references are preserved in
    document order.
    """
    try:
        doc = safe_load(text)
    except Exception:                              # noqa: BLE001
        # PyYAML raises a wide tree of exceptions on malformed input;
        # any of them means "not walkable" here.
        return None
    if not isinstance(doc, (dict, list)):
        return None
    out: list[str] = []
    # Anchors/aliases make the parsed object graph a DAG (or, for
    # recursive anchors, cyclic) — track visited container ids so a
    # hostile document can't loop or blow up the walk.  FIFO queue =
    # breadth-first in document order, deterministic output.
    seen: set[int] = set()
    queue: list[object] = [doc]
    cursor = 0
    while cursor < len(queue):
        node = queue[cursor]
        cursor += 1
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "uses" and isinstance(value, str):
                    out.append(value.strip())
                if isinstance(value, (dict, list)):
                    queue.append(value)
        elif isinstance(node, list):
            queue.extend(
                item for item in node if isinstance(item, (dict, list))
            )
    return out


def best_effort_line(text: str, spec: str) -> int:
    """First 1-based line whose text contains ``spec`` (or, failing
    that, the spec's action name) — used for walk-only hits, where
    the YAML parse has no positions.  Falls back to line 1."""
    for line_no, line in enumerate(split_lines(text), start=1):
        if spec in line:
            return line_no
    action = spec.rsplit("@", 1)[0]
    if action:
        for line_no, line in enumerate(split_lines(text), start=1):
            if action in line:
                return line_no
    return 1


__all__ = ["best_effort_line", "extract_uses_specs"]
