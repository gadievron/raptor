"""Method-span helper for cross-method candidate scoping (wave b38).

One question, answered from the tree-sitter AST: which method or
constructor declaration encloses a given line, and what is its full
line span? The sanitizer-cut post-pass uses this to scope traceless
source candidates to the sink's enclosing method.

Soundness note (the engine fact this module exists to encode): a
traceless finding is on the reconstruction path because its producer's
taint analysis is intra-procedural — producers that track flows across
methods emit dataflow traces, and trace-carrying findings never reach
the reconstruction path. A candidate line outside the sink's method
therefore cannot be the withheld trace's source, so excluding it never
hides evidence the producer could have used. Trace-carrying findings
must NOT be scoped with this helper.
"""

from __future__ import annotations

from typing import Optional, Tuple

__all__ = ["enclosing_method_span"]

_METHOD_TYPES = ("method_declaration", "constructor_declaration")


def _get_parser():
    try:
        from core.analysis.cfg_builder_java import _get_parser as _p
        return _p()
    except Exception:  # noqa: BLE001 — grammar optional; callers degrade
        return None


def enclosing_method_span(
    source_text: str, lineno: int,
) -> Optional[Tuple[str, int, int]]:
    """Smallest method/constructor declaration containing *lineno*.

    Returns ``(name, start_line, end_line)`` (1-based, inclusive) or
    ``None`` when no declaration contains the line or the grammar is
    unavailable. The start line matches
    :func:`core.analysis.cfg_builder_java.find_enclosing_method`'s
    header-line convention, so ``source_line == start_line`` triggers
    the resolver's params-entry semantics.
    """
    parser = _get_parser()
    if parser is None:
        return None
    tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    best: Optional[Tuple[int, str, int, int]] = None
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in _METHOD_TYPES:
            continue
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        if not (start <= lineno <= end):
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        span = end - start
        if best is None or span < best[0]:
            name = source_text.encode("utf-8", errors="replace")[
                name_node.start_byte:name_node.end_byte
            ].decode("utf-8", errors="replace")
            best = (span, name, start, end)
    if best is None:
        return None
    return best[1], best[2], best[3]
