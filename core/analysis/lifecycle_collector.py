"""Collect write-site and read-site guards for state fields.

Uses the existing CFG + dominator infrastructure to extract the
conjunction of guard conditions dominating each write or read site.
"""

from __future__ import annotations

import logging
import re
from core.source.lines import split_lines

from .cfg_conditions import _CONDITION_LABEL_RE, extract_references
from .lifecycle_model import Guard, ReadSite, WriteSite

logger = logging.getLogger(__name__)


def _extract_condition_from_label(label: str) -> str | None:
    """Extract the condition text from a CFG node label like
    'If (x != NULL)' or the C builder's bare 'For x < n'.

    One authority: :data:`core.analysis.cfg_conditions._CONDITION_LABEL_RE`
    owns the label grammar — a private copy here drifted when the
    ``For`` / bare-condition forms were added there, silently dropping
    every C for-loop guard from the collected sets (false-negative
    direction).
    """
    m = _CONDITION_LABEL_RE.match(label.strip())
    if m:
        return (m.group(1) or m.group(2) or "").strip()
    return None


def _find_node_at_line(cfg, line: int):
    """Find the CFG node closest to the given source line."""
    from .cfg_utils import find_node_at_line
    return find_node_at_line(cfg, line)


class GuardEpochUnavailable(RuntimeError):
    """A collected branch premise cannot describe the values at the site."""


_MAX_GUARD_EPOCH_VISITS = 50_000


def _require_stable_guard_epochs(cfg, target, facts) -> None:
    """Decline relevant stores and opaque effects before statement entry.

    Re-entering the branch would re-test the premise, so that entry is
    excluded from the walk. Effects after an acyclic target or on dead
    sibling paths cannot invalidate its entry values. Target-return cycles
    remain relevant when the same guard is not re-tested.
    """
    generic_effects = set()
    definitions = {}
    for node in cfg.nodes():
        if getattr(node, "calls", ()) or getattr(node, "may_escape", False):
            generic_effects.add(node)
        for name in getattr(node, "defs", ()):
            definitions.setdefault(name, set()).add(node)
    visits = 0
    for fact in facts:
        references = extract_references(fact.condition)
        if not references:
            continue
        relevant_stores = set()
        for name in references:
            relevant_stores.update(definitions.get(name, ()))
        visits += len(generic_effects) + len(relevant_stores) + len(references)
        if visits > _MAX_GUARD_EPOCH_VISITS:
            raise GuardEpochUnavailable("guard value stability walk budget exhausted")
        target_effectful = target in generic_effects or target in relevant_stores
        candidates = (generic_effects | relevant_stores) - {fact.branch, target}
        if not candidates and not target_effectful:
            continue
        forward = {fact.branch}
        pending = [fact.branch]
        predecessors = {}
        while pending:
            node = pending.pop()
            visits += 1
            if visits > _MAX_GUARD_EPOCH_VISITS:
                raise GuardEpochUnavailable("guard value stability walk budget exhausted")
            for successor in cfg.successors(node):
                if successor == fact.branch:
                    continue
                predecessors.setdefault(successor, set()).add(node)
                if successor not in forward:
                    forward.add(successor)
                    pending.append(successor)
        backward = {target}
        pending = [target]
        while pending:
            node = pending.pop()
            visits += 1
            if visits > _MAX_GUARD_EPOCH_VISITS:
                raise GuardEpochUnavailable("guard value stability walk budget exhausted")
            if node in candidates:
                raise GuardEpochUnavailable("guard value may change on a branch-to-site path")
            for predecessor in predecessors.get(node, ()):
                if predecessor not in backward:
                    backward.add(predecessor)
                    pending.append(predecessor)
        # Target effects happen after its first entry, but a return cycle
        # can carry them to a later invocation under the same old premise.
        if target_effectful and any(
            successor != fact.branch and successor in backward
            for successor in cfg.successors(target)
        ):
            raise GuardEpochUnavailable("effectful site can repeat without rechecking guard values")


def collect_guards_at_site(
    cfg,
    dom_tree,
    line: int,
    file_path: str,
) -> frozenset[Guard]:
    """Extract the set of guard conditions dominating a given line.

    Walks the dominator tree from the target node back to entry,
    collecting condition-bearing nodes (if/while/elif).

    Source-built branch facts additionally require stable referenced values
    up to the site. ``GuardEpochUnavailable`` means unknown evidence, not an
    empty guard conjunction.
    """
    target_node = _find_node_at_line(cfg, line)
    if target_node is None:
        return frozenset()

    dominators = dom_tree.dominators_of(target_node)
    branch_guards = getattr(cfg, "branch_guards", None)
    if branch_guards is not None:
        # A selected branch entry must dominate the site. Domination by
        # the condition's evaluation alone says nothing about its truth.
        active_facts = tuple(fact for fact in branch_guards if fact.branch in dominators)
        _require_stable_guard_epochs(cfg, target_node, active_facts)
        return frozenset(Guard(
            condition=fact.condition, file=file_path, line=fact.line,
            polarity=fact.polarity,
        ) for fact in active_facts)
    guards: set[Guard] = set()

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
    _file_path: str,
    field_name: str,
    struct_type: str = "",  # noqa: ARG001
) -> dict[str, list[int]]:
    """Scan source text for write and read sites of a field.

    Returns {"writes": [line, ...], "reads": [line, ...]}.
    Uses heuristic pattern matching — arrow/dot access with assignment
    vs use context.
    """
    writes: list[int] = []
    reads: list[int] = []

    access_patterns = [
        re.compile(rf"->({re.escape(field_name)})\b"),
        re.compile(rf"\.({re.escape(field_name)})\b"),
    ]

    assign_patterns = [
        re.compile(rf"->({re.escape(field_name)})\s*=(?!=)"),
        re.compile(rf"\.({re.escape(field_name)})\s*=(?!=)"),
    ]

    for lineno, line_text in enumerate(split_lines(source), 1):
        is_write = any(p.search(line_text) for p in assign_patterns)
        is_access = any(p.search(line_text) for p in access_patterns)

        if is_write:
            writes.append(lineno)
        if is_access:
            reads.append(lineno)

    return {"writes": writes, "reads": reads}
