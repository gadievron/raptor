"""Project-specific sink discovery via call-graph heuristics.

Supplements the taxonomy-based sink discovery in
``core.inventory.sink_discovery`` by finding project-specific sinks:
functions that wrap known dangerous APIs and are themselves called
with attacker-controlled input.  These wrappers are invisible to the
taxonomy (they're project-unique names) but are just as dangerous as
the underlying API — any bug in the wrapper IS the vulnerability.

Discovery strategy:
1. **Wrapper sinks**: functions that directly call a taxonomy sink
   (distance=1) and are themselves called by 2+ callers.  The wrapper
   abstracts the dangerous operation, making it a project-specific sink.
2. **Naming heuristics**: functions whose names suggest security-relevant
   operations (``execute``, ``query``, ``render``, ``deserialize``,
   ``eval``, ``dispatch``, ``run_command``) but aren't in the taxonomy.
3. **Side-effect wrappers**: functions that call file/network/process
   APIs and are reachable from entry points via the call graph.

Each discovered sink gets a confidence level:
- HIGH: wrapper around a taxonomy sink with taint evidence
- MEDIUM: wrapper without taint evidence, or naming heuristic with
  a dangerous callee
- LOW: naming heuristic only (no structural evidence)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

_WRAPPER_NAME_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"(?:^|_)(?:exec|execute|run|eval|do_query)(?:$|_)", re.I),
    re.compile(r"(?:^|_)(?:query|sql|db_|database)(?:$|_)", re.I),
    re.compile(r"(?:^|_)(?:render|template|format_html)(?:$|_)", re.I),
    re.compile(r"(?:^|_)(?:deseriali[sz]e|unpickle|unmarshal|decode_obj)(?:$|_)", re.I),
    re.compile(r"(?:^|_)(?:dispatch|invoke|call_handler|process_cmd)(?:$|_)", re.I),
    re.compile(r"(?:^|_)(?:write_file|read_file|open_file|serve_file)(?:$|_)", re.I),
    re.compile(r"(?:^|_)(?:send_request|http_get|http_post|fetch_url)(?:$|_)", re.I),
    re.compile(r"(?:^|_)(?:run_command|shell|spawn|popen)(?:$|_)", re.I),
]

_SIDE_EFFECT_TARGETS: FrozenSet[str] = frozenset({
    "fopen", "fwrite", "fread", "open", "write", "read",
    "send", "recv", "sendto", "recvfrom", "connect", "bind",
    "system", "popen", "exec", "execve", "execvp",
    "fclose", "unlink", "remove", "rename", "mkdir", "rmdir",
    "chmod", "chown", "mmap", "munmap",
    "socket", "listen", "accept",
    "ioctl", "fcntl",
    "dlopen", "dlsym",
})


@dataclass
class DiscoveredSink:
    """A project-specific sink found via heuristics."""

    file: str
    function: str
    reason: str
    confidence: str
    wraps: List[str] = field(default_factory=list)
    caller_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "file": self.file,
            "function": self.function,
            "reason": self.reason,
            "confidence": self.confidence,
        }
        if self.wraps:
            d["wraps"] = self.wraps
        if self.caller_count:
            d["caller_count"] = self.caller_count
        return d


@dataclass
class SinkHeuristicsResult:
    """Result of project-specific sink discovery."""

    discovered: List[DiscoveredSink] = field(default_factory=list)
    wrapper_count: int = 0
    naming_count: int = 0
    side_effect_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "discovered_sinks": [s.to_dict() for s in self.discovered],
            "counts": {
                "total": len(self.discovered),
                "wrapper": self.wrapper_count,
                "naming": self.naming_count,
                "side_effect": self.side_effect_count,
            },
        }


def discover_project_sinks(
    sink_results: Any,
    call_graphs: Optional[Dict[str, Any]] = None,
    taint_approx: Optional[Dict[str, Any]] = None,
    *,
    min_callers_for_wrapper: int = 2,
    entry_points: Optional[Set[Tuple[str, str]]] = None,
) -> SinkHeuristicsResult:
    """Discover project-specific sinks from call-graph structure.

    Parameters
    ----------
    sink_results
        Output of ``core.inventory.sink_discovery.discover_sinks()``.
        Provides the taxonomy sink set and call-graph edges.
    call_graphs
        Per-file call graphs (mapping path → FileCallGraph).
        Used for wrapper detection when available.
    taint_approx
        Per-function taint approximation results.
        When present, upgrades wrapper confidence from MEDIUM to HIGH.
    min_callers_for_wrapper
        A wrapper function must have at least this many callers to be
        considered a project-specific sink.  Avoids promoting single-use
        internal helpers.
    """
    result = SinkHeuristicsResult()

    taxonomy_keys = _extract_taxonomy_keys(sink_results)
    direct_sink_targets = _extract_direct_sink_targets(sink_results)
    forward_edges, reverse_edges = _build_edge_maps(call_graphs)

    seen: Set[Tuple[str, str]] = set()

    _discover_wrappers(
        result, sink_results, forward_edges, reverse_edges,
        direct_sink_targets, taxonomy_keys, taint_approx,
        min_callers_for_wrapper, seen,
    )

    _discover_by_naming(
        result, call_graphs, taxonomy_keys,
        direct_sink_targets, seen,
    )

    _discover_side_effect_wrappers(
        result, call_graphs, taxonomy_keys, seen,
        entry_points=entry_points,
        reverse_edges=reverse_edges,
    )

    result.discovered.sort(
        key=lambda s: (
            {"high": 0, "medium": 1, "low": 2}.get(s.confidence, 3),
            -s.caller_count,
        ),
    )

    return result


def _extract_taxonomy_keys(
    sink_results: Any,
) -> Set[Tuple[str, str]]:
    """Get the set of (file, function) already identified by taxonomy."""
    keys: Set[Tuple[str, str]] = set()
    if sink_results is None:
        return keys
    if hasattr(sink_results, "direct_sinks"):
        for s in sink_results.direct_sinks:
            keys.add((s.file, s.function))
    return keys


def _extract_direct_sink_targets(
    sink_results: Any,
) -> Dict[Tuple[str, str], List[str]]:
    """Map (file, function) → list of dangerous targets called."""
    targets: Dict[Tuple[str, str], List[str]] = {}
    if sink_results is None:
        return targets
    if hasattr(sink_results, "direct_sinks"):
        for s in sink_results.direct_sinks:
            key = (s.file, s.function)
            targets.setdefault(key, []).append(s.target)
    return targets


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Attribute or dict-key lookup (handles both dataclasses and dicts)."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _build_edge_maps(
    call_graphs: Optional[Dict[str, Any]],
) -> Tuple[
    Dict[Tuple[str, str], Set[Tuple[str, str]]],
    Dict[Tuple[str, str], Set[Tuple[str, str]]],
]:
    """Build forward and reverse call edges from call graphs."""
    forward: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
    reverse: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
    if call_graphs is None:
        return forward, reverse

    for filepath, graph in call_graphs.items():
        calls = _get(graph, "calls", [])
        for call in calls:
            caller = _get(call, "caller") or "<module>"
            chain = _get(call, "chain", [])
            callee = ".".join(chain) if isinstance(chain, list) else str(chain)
            if not callee:
                continue
            caller_key = (filepath, caller)
            callee_key = (filepath, callee)
            forward.setdefault(caller_key, set()).add(callee_key)
            reverse.setdefault(callee_key, set()).add(caller_key)

    return forward, reverse


def _discover_wrappers(
    result: SinkHeuristicsResult,
    sink_results: Any,
    forward_edges: Dict[Tuple[str, str], Set[Tuple[str, str]]],
    reverse_edges: Dict[Tuple[str, str], Set[Tuple[str, str]]],
    direct_sink_targets: Dict[Tuple[str, str], List[str]],
    taxonomy_keys: Set[Tuple[str, str]],
    taint_approx: Optional[Dict[str, Any]],
    min_callers: int,
    seen: Set[Tuple[str, str]],
) -> None:
    """Find functions that wrap taxonomy sinks and are widely called."""
    if not direct_sink_targets:
        return

    name_callers = _count_callers_by_name(reverse_edges)

    for sink_key, targets in direct_sink_targets.items():
        callers = reverse_edges.get(sink_key, set())
        for caller_key in callers:
            if caller_key in taxonomy_keys:
                continue
            if caller_key in seen:
                continue

            total_callers = name_callers.get(caller_key[1], 0)
            if total_callers < min_callers:
                continue

            has_taint = False
            if taint_approx:
                taint_key = f"{caller_key[0]}:{caller_key[1]}"
                if taint_key in taint_approx:
                    approx = taint_approx[taint_key]
                    flows = getattr(approx, "direct_flows", None) or []
                    if flows:
                        has_taint = True

            confidence = "high" if has_taint else "medium"
            result.discovered.append(DiscoveredSink(
                file=caller_key[0],
                function=caller_key[1],
                reason="wrapper",
                confidence=confidence,
                wraps=targets,
                caller_count=total_callers,
            ))
            result.wrapper_count += 1
            seen.add(caller_key)


def _count_callers_by_name(
    reverse_edges: Dict[Tuple[str, str], Set[Tuple[str, str]]],
) -> Dict[str, int]:
    """Count how many callers each function name has across all files."""
    counts: Dict[str, int] = {}
    for (_, callee_name), callers in reverse_edges.items():
        counts[callee_name] = counts.get(callee_name, 0) + len(callers)
    return counts


def _discover_by_naming(
    result: SinkHeuristicsResult,
    call_graphs: Optional[Dict[str, Any]],
    taxonomy_keys: Set[Tuple[str, str]],
    direct_sink_targets: Dict[Tuple[str, str], List[str]],
    seen: Set[Tuple[str, str]],
) -> None:
    """Find functions with security-suggestive names."""
    if call_graphs is None:
        return

    for filepath, graph in call_graphs.items():
        calls = _get(graph, "calls", [])
        callers_in_file: Set[str] = set()
        callee_map: Dict[str, Set[str]] = {}

        for call in calls:
            caller = _get(call, "caller") or "<module>"
            callers_in_file.add(caller)
            chain = _get(call, "chain", [])
            callee = ".".join(chain) if isinstance(chain, list) else str(chain)
            if callee:
                callee_map.setdefault(caller, set()).add(callee)

        for func in callers_in_file:
            key = (filepath, func)
            if key in seen or key in taxonomy_keys:
                continue

            if not _matches_sink_name(func):
                continue

            callees = callee_map.get(func, set())
            has_dangerous_callee = any(
                _is_side_effect_target(c) for c in callees
            )

            confidence = "medium" if has_dangerous_callee else "low"
            result.discovered.append(DiscoveredSink(
                file=filepath,
                function=func,
                reason="naming",
                confidence=confidence,
            ))
            result.naming_count += 1
            seen.add(key)


def _discover_side_effect_wrappers(
    result: SinkHeuristicsResult,
    call_graphs: Optional[Dict[str, Any]],
    taxonomy_keys: Set[Tuple[str, str]],
    seen: Set[Tuple[str, str]],
    *,
    entry_points: Optional[Set[Tuple[str, str]]] = None,
    reverse_edges: Optional[Dict[Tuple[str, str], Set[Tuple[str, str]]]] = None,
) -> None:
    """Find functions that call side-effecting system APIs.

    When *entry_points* and *reverse_edges* are provided, only discovers
    side-effect wrappers that are transitively reachable from at least one
    entry point — an unreachable side-effect function isn't an attack surface
    sink.  Without these args, all side-effect wrappers are included (the
    prior behaviour).
    """
    if call_graphs is None:
        return

    reachable: Optional[Set[Tuple[str, str]]] = None
    if entry_points and reverse_edges:
        reachable = _compute_reachable_from_entries(entry_points, reverse_edges)

    for filepath, graph in call_graphs.items():
        calls = _get(graph, "calls", [])
        func_callees: Dict[str, Set[str]] = {}

        for call in calls:
            caller = _get(call, "caller") or "<module>"
            chain = _get(call, "chain", [])
            callee = ".".join(chain) if isinstance(chain, list) else str(chain)
            if callee:
                func_callees.setdefault(caller, set()).add(callee)

        for func, callees in func_callees.items():
            key = (filepath, func)
            if key in seen or key in taxonomy_keys:
                continue

            if reachable is not None and key not in reachable:
                continue

            side_effects = [c for c in callees if _is_side_effect_target(c)]
            if not side_effects:
                continue

            result.discovered.append(DiscoveredSink(
                file=filepath,
                function=func,
                reason="side_effect",
                confidence="medium",
                wraps=side_effects[:5],
            ))
            result.side_effect_count += 1
            seen.add(key)


def _compute_reachable_from_entries(
    entry_points: Set[Tuple[str, str]],
    reverse_edges: Dict[Tuple[str, str], Set[Tuple[str, str]]],
    *,
    max_depth: int = 20,
) -> Set[Tuple[str, str]]:
    """BFS forward from entry points through reverse_edges (caller→callee)."""
    forward: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
    for callee, callers in reverse_edges.items():
        for caller in callers:
            forward.setdefault(caller, set()).add(callee)

    reachable: Set[Tuple[str, str]] = set(entry_points)
    frontier = list(entry_points)
    depth = 0
    while frontier and depth < max_depth:
        next_frontier: List[Tuple[str, str]] = []
        for node in frontier:
            for child in forward.get(node, ()):
                if child not in reachable:
                    reachable.add(child)
                    next_frontier.append(child)
        frontier = next_frontier
        depth += 1
    return reachable


def _matches_sink_name(name: str) -> bool:
    """Check if a function name matches security-relevant patterns."""
    return any(p.search(name) for p in _WRAPPER_NAME_PATTERNS)


def _is_side_effect_target(callee: str) -> bool:
    """Check if a callee is a known side-effecting system API."""
    bare = callee.rsplit(".", 1)[-1] if "." in callee else callee
    return bare in _SIDE_EFFECT_TARGETS


def merge_discovered_sinks(
    sink_results: Any,
    heuristic_results: SinkHeuristicsResult,
) -> None:
    """Merge heuristic discoveries into the taxonomy-based results.

    Adds discovered sinks as SinkInfo entries with ``direct=False``
    to distinguish them from taxonomy-matched sinks.
    """
    if sink_results is None or not heuristic_results.discovered:
        return

    try:
        from core.inventory.sink_discovery import SinkInfo
    except ImportError:
        return

    if not hasattr(sink_results, "direct_sinks"):
        return

    existing = set()
    for s in sink_results.direct_sinks:
        existing.add((s.file, s.function))

    for disc in heuristic_results.discovered:
        key = (disc.file, disc.function)
        if key in existing:
            continue

        target_desc = ", ".join(disc.wraps) if disc.wraps else disc.reason
        sink_results.direct_sinks.append(SinkInfo(
            file=disc.file,
            function=disc.function,
            line=0,
            target=f"[project] {target_desc}",
            direct=False,
        ))
