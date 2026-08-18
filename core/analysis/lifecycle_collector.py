"""Collect write-site and read-site guards for state fields.

Uses the existing CFG + dominator infrastructure to extract the
conjunction of guard conditions dominating each write or read site.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, FrozenSet, List, Optional, Set

from .lifecycle_model import Guard, ReadSite, WriteSite

logger = logging.getLogger(__name__)

_IF_CONDITION_RE = re.compile(
    r"^(?:If|While|ElIf)\s*\((.+)\)$",
    re.IGNORECASE,
)


def _extract_condition_from_label(label: str) -> Optional[str]:
    """Extract the condition text from a CFG node label like 'If (x != NULL)'."""
    m = _IF_CONDITION_RE.match(label.strip())
    if m:
        return m.group(1).strip()
    return None


def _find_node_at_line(cfg, line: int):
    """Find the CFG node closest to the given source line."""
    from .cfg_utils import find_node_at_line
    return find_node_at_line(cfg, line)


def collect_guards_at_site(
    cfg,
    dom_tree,
    line: int,
    file_path: str,
) -> FrozenSet[Guard]:
    """Extract the set of guard conditions dominating a given line.

    Walks the dominator tree from the target node back to entry,
    collecting condition-bearing nodes (if/while/elif).
    """
    target_node = _find_node_at_line(cfg, line)
    if target_node is None:
        return frozenset()

    dominators = dom_tree.dominators_of(target_node)
    guards: Set[Guard] = set()

    for dom_node in dominators:
        cond = _extract_condition_from_label(dom_node.label)
        if cond:
            guards.add(Guard(
                condition=cond,
                file=file_path,
                line=dom_node.lineno,
            ))

    return frozenset(guards)


def collect_write_site(
    cfg,
    dom_tree,
    file_path: str,
    function_name: str,
    line: int,
) -> WriteSite:
    """Build a WriteSite with its dominating guards."""
    guards = collect_guards_at_site(cfg, dom_tree, line, file_path)
    return WriteSite(
        file=file_path,
        line=line,
        function=function_name,
        guards=guards,
    )


def collect_read_site(
    cfg,
    dom_tree,
    file_path: str,
    function_name: str,
    line: int,
    security_relevant: bool = True,
) -> ReadSite:
    """Build a ReadSite with its dominating guards."""
    guards = collect_guards_at_site(cfg, dom_tree, line, file_path)
    return ReadSite(
        file=file_path,
        line=line,
        function=function_name,
        guards=guards,
        security_relevant=security_relevant,
    )


def collect_field_sites_from_source(
    source: str,
    file_path: str,
    field_name: str,
    struct_type: str = "",  # noqa: ARG001
) -> Dict[str, List[int]]:
    """Scan source text for write and read sites of a field.

    Returns {"writes": [line, ...], "reads": [line, ...]}.
    Uses heuristic pattern matching — arrow/dot access with assignment
    vs use context.
    """
    writes: List[int] = []
    reads: List[int] = []

    access_patterns = [
        re.compile(rf"->({re.escape(field_name)})\b"),
        re.compile(rf"\.({re.escape(field_name)})\b"),
    ]

    assign_patterns = [
        re.compile(rf"->({re.escape(field_name)})\s*=(?!=)"),
        re.compile(rf"\.({re.escape(field_name)})\s*=(?!=)"),
    ]

    for lineno, line_text in enumerate(source.splitlines(), 1):
        is_write = any(p.search(line_text) for p in assign_patterns)
        is_access = any(p.search(line_text) for p in access_patterns)

        if is_write:
            writes.append(lineno)
        if is_access:
            reads.append(lineno)

    return {"writes": writes, "reads": reads}
