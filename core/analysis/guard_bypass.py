"""Guard-bypass query (PR3).

Answers: "does any CFG path from a source node to a sink node bypass
all guards constraining the source variable?"

Uses the existing PythonCFG/CPPCFG + DomTree, extended with
ControlCondition from core/analysis/cfg_conditions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from collections.abc import Callable

from .cfg_conditions import ConditionEdge, ControlCondition, extract_conditions_from_cfg

logger = logging.getLogger(__name__)

_MAX_PATHS = 256
_MAX_DEPTH = 50


@dataclass(frozen=True)
class Guard:
    """A guard condition that constrains a variable."""

    condition: ControlCondition
    node_line: int

    def to_dict(self):
        return {
            "condition": self.condition.to_dict(),
            "node_line": self.node_line,
        }


@dataclass
class GuardBypassResult:
    """Result of a guard-bypass query."""

    bypassable_paths: list[list[int]] = field(default_factory=list)
    constraining_guards: list[Guard] = field(default_factory=list)
    must_visit_guards: list[Guard] = field(default_factory=list)
    smt_verdict: str | None = None
    confidence: str = "structural"

    def is_bypassed(self) -> bool:
        return len(self.bypassable_paths) > 0

    def to_dict(self):
        return {
            "bypassable_paths": self.bypassable_paths,
            "constraining_guards": [g.to_dict() for g in self.constraining_guards],
            "must_visit_guards": [g.to_dict() for g in self.must_visit_guards],
            "smt_verdict": self.smt_verdict,
            "confidence": self.confidence,
        }


GuardClassifier = Callable[[ControlCondition, str], bool]


def _default_guard_classifier(condition: ControlCondition, variable: str) -> bool:
    """Default: a condition constrains a variable if the variable
    appears in the condition's references."""
    return variable in condition.references


def _find_node_at_line(cfg, line: int):
    """Find the CFG node at or nearest to the given line."""
    from .cfg_utils import find_node_at_line
    return find_node_at_line(cfg, line)


def _find_guards(
    _cfg,
    condition_edges: list[ConditionEdge],
    source_var: str,
    guard_classifier: GuardClassifier,
) -> list[Guard]:
    """Find all guards in the CFG that constrain the source variable."""
    guards: list[Guard] = []
    seen: set[tuple[str, int]] = set()

    for edge in condition_edges:
        if edge.condition is None:
            continue
        if guard_classifier(edge.condition, source_var):
            key = (edge.condition.text, edge.src_line)
            if key not in seen:
                seen.add(key)
                guards.append(Guard(
                    condition=edge.condition,
                    node_line=edge.src_line,
                ))

    return guards


def _enumerate_paths(
    cfg,
    source_node,
    sink_node,
    max_paths: int = _MAX_PATHS,
    max_depth: int = _MAX_DEPTH,
) -> tuple[list[list[int]], bool]:
    """Bounded DFS from source to sink. Returns (paths, complete).

    complete is False if the path cap was hit (confidence degrades).
    """
    paths: list[list[int]] = []
    complete = True

    stack: list[tuple[object, list[int], set[int]]] = [
        (source_node, [source_node.lineno], {id(source_node)}),
    ]

    while stack:
        if len(paths) >= max_paths:
            complete = False
            break

        node, path, visited = stack.pop()
        if node is sink_node:
            paths.append(list(path))
            continue

        if len(path) >= max_depth:
            complete = False
            continue

        for succ in cfg.successors(node):
            if id(succ) not in visited:
                new_visited = visited | {id(succ)}
                stack.append((succ, path + [succ.lineno], new_visited))

    return paths, complete


def _guard_on_path(
    path_lines: list[int],
    guard: Guard,
) -> bool:
    """Check if a guard's node line appears on the path."""
    return guard.node_line in path_lines


def query(
    cfg,
    source_var: str,
    source_line: int,
    sink_line: int,
    guard_classifier: GuardClassifier | None = None,
) -> GuardBypassResult:
    """Query whether any path from source to sink bypasses guards
    constraining source_var.

    Args:
        cfg: PythonCFG or CPPCFG instance.
        source_var: variable name to track.
        source_line: line number of source definition.
        sink_line: line number of sink consumption.
        guard_classifier: predicate deciding if a condition constrains
            source_var. Defaults to reference-based check.

    Returns:
        GuardBypassResult with bypassable paths and guard inventory.
    """
    classifier = guard_classifier or _default_guard_classifier

    source_node = _find_node_at_line(cfg, source_line)
    sink_node = _find_node_at_line(cfg, sink_line)

    if source_node is None or sink_node is None:
        return GuardBypassResult(confidence="incomplete")

    condition_edges = extract_conditions_from_cfg(cfg)
    guards = _find_guards(cfg, condition_edges, source_var, classifier)

    if not guards:
        paths, complete = _enumerate_paths(cfg, source_node, sink_node)
        return GuardBypassResult(
            bypassable_paths=paths,
            constraining_guards=[],
            must_visit_guards=[],
            confidence="structural" if complete else "incomplete",
        )

    paths, complete = _enumerate_paths(cfg, source_node, sink_node)

    if not paths:
        return GuardBypassResult(
            bypassable_paths=[],
            constraining_guards=guards,
            must_visit_guards=[],
            confidence="structural" if complete else "incomplete",
        )

    bypassable: list[list[int]] = []
    must_visit: set[int] = set(range(len(guards)))

    for path in paths:
        guards_on_path = set()
        for i, guard in enumerate(guards):
            if _guard_on_path(path, guard):
                guards_on_path.add(i)

        if not guards_on_path:
            bypassable.append(path)

        must_visit &= guards_on_path

    must_visit_guards = [guards[i] for i in sorted(must_visit)]

    return GuardBypassResult(
        bypassable_paths=bypassable,
        constraining_guards=guards,
        must_visit_guards=must_visit_guards,
        confidence="structural" if complete else "incomplete",
    )


def check_guard_coverage(
    cfg,
    read_line: int,
    required_guard_text: str,
) -> bool:
    """Check if a required guard dominates all paths to a read site.

    Simplified query for lifecycle-precondition checks: does the
    given guard condition appear on every path from entry to
    read_line?

    Returns True if the guard is on every path (no bypass).
    """
    read_node = _find_node_at_line(cfg, read_line)
    if read_node is None:
        return False

    entry_node = cfg.entry_node if hasattr(cfg, "entry_node") else cfg.entry
    condition_edges = extract_conditions_from_cfg(cfg)

    guard_lines: set[int] = set()
    for edge in condition_edges:
        if edge.condition is None:
            continue
        if edge.condition.text.strip().lower() == required_guard_text.strip().lower():
            guard_lines.add(edge.src_line)

    if not guard_lines:
        return False

    paths, complete = _enumerate_paths(cfg, entry_node, read_node)
    if not paths:
        # No enumerated paths is only vacuous coverage ("read site
        # unreachable, nothing to guard") when the DFS actually
        # completed. When the depth/path cap truncated enumeration,
        # the absence of paths is an artifact of the bound, not a
        # reachability fact — answer "not covered" so callers fall
        # back to their weaker textual check instead of dropping
        # findings as structurally covered. Mirrors query()'s
        # confidence degradation to "incomplete" on truncation.
        return complete

    for path in paths:
        if not any(line in guard_lines for line in path):
            return False

    # Every ENUMERATED path carries the guard — but when the DFS was
    # truncated (path cap or depth bound), unenumerated or deeper
    # paths may bypass it. "Covered on every path" is a universal
    # claim; an incomplete enumeration cannot support it, and the
    # consumer (lifecycle_checker) DROPS a missing-guard finding on
    # True. Answer "not covered" so it falls back to its weaker
    # textual check. Mirrors query()'s confidence degradation and the
    # truncated-with-zero-paths branch above.
    return complete
