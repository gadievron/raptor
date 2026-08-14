"""Attack-surface-aware priority scoring for audit gaps.

Provides a secondary priority signal beyond the basic tier in gaps.py.
Uses context-map entry points, sinks, trust boundaries, and flow traces
to compute a numeric score per function that reflects proximity to the
attack surface.

Scoring model:
  +10  Entry point (directly receives untrusted input)
  +8   Sink (security-sensitive operation)
  +6   Trust boundary (crosses privilege domains)
  +5   On a traced flow path (source → sink path passes through)
  +8   Large internal function (≥200 SLOC; parsers, state machines)
  +4   Complex function (≥80 SLOC)
  +3   Callee of an entry point (1-hop from attack surface)
  +2   Moderate function (≥30 SLOC)
  +2   Has unchecked flows (context-map flagged unchecked)
  +1   In a file with any entry point

Higher score = review first. Ties broken by SLOC (larger = more surface).

Reuse: Both /audit skill (via gaps --prioritize) and the orchestrator
call score_functions() to order work.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from ._util import extract_context_map_set

logger = logging.getLogger(__name__)

SCORE_ENTRY_POINT = 10
SCORE_SINK = 8
SCORE_TRUST_BOUNDARY = 6
SCORE_ON_FLOW_PATH = 5
SCORE_NO_TOOL_COVERAGE = 4
SCORE_TOOL_FAILED = 4
SCORE_CALLEE_OF_ENTRY = 3
SCORE_EXPORTED = 2
SCORE_PARTIAL_TOOL_COVERAGE = 2
SCORE_NOT_FUZZED = 2
SCORE_UNCHECKED_FLOW = 2
SCORE_FILE_HAS_ENTRY_POINT = 1
SCORE_NEW_CODE = 3
SCORE_THREAT_MODEL_FOCUS = 5
SCORE_OPEN_CONSTRAINT = 4
SCORE_COMPLEX = 4
SCORE_MODERATE = 2
SCORE_LARGE_INTERNAL = 8
SCORE_STRATEGY_MAX_BOOST = 5
SCORE_BINARY_SINK = 6
SCORE_BINARY_SURFACE = 4
SCORE_PARSER_BOUNDARY = 3

_COMPLEX_SLOC = 80
_MODERATE_SLOC = 30
_LARGE_SLOC = 200

_EXPORTED_VISIBILITY = frozenset({"extern", "exported", "public"})


def score_functions(
    gaps: List[Dict[str, Any]],
    *,
    context_map: Optional[Dict[str, Any]] = None,
    flow_traces: Optional[List[Dict[str, Any]]] = None,
    tool_coverage: Optional[Dict[str, Set[str]]] = None,
    tool_failures: Optional[Set[str]] = None,
    fuzz_coverage: Optional[Set[str]] = None,
    new_functions: Optional[Set[str]] = None,
    threat_model: Optional[Dict[str, Any]] = None,
    open_constraint_keys: Optional[Set[str]] = None,
    strategy_weights: Optional[Dict[str, float]] = None,
    binary_bridge: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Score and re-sort gaps by attack-surface proximity.

    Each gap gets a numeric 'priority_score' field (higher = more urgent).
    The original 'priority' tier is preserved for grouping; score provides
    ordering within the same tier.

    Args:
        gaps: Gap list from compute_gaps().
        context_map: Parsed context-map.json (entry_points, sinks, etc.)
        flow_traces: List of parsed flow-trace-*.json dicts.
        tool_coverage: {file_path: set_of_tool_names} — files with no tools
            get SCORE_NO_TOOL_COVERAGE, files with only one tool get
            SCORE_PARTIAL_TOOL_COVERAGE.
        new_functions: Set of file:function keys from inventory diff
            (added or modified functions). Gets SCORE_NEW_CODE.
        threat_model: Parsed threat model dict.  When it carries a
            ``focus_cwes`` list, functions whose CWE matches get
            SCORE_THREAT_MODEL_FOCUS.
        strategy_weights: Per-strategy weight multipliers from past runs.
            Strategies with weight > 1.0 boost the function's score;
            strategies with weight < 1.0 are deprioritized.
        binary_bridge: BinaryBridgeResult from binary analysis output.
            Binary-confirmed sink callers, ranked surfaces, and parser
            boundaries boost the function's score.

    Returns:
        Gaps sorted by (priority ASC, priority_score DESC, sloc DESC).
    """
    entry_points = extract_context_map_set(context_map, "entry_points")
    sinks = extract_context_map_set(context_map, "sinks")
    trust_boundaries = extract_context_map_set(
        context_map, "trust_boundaries", nested_key="functions",
    )
    unchecked_flows = _extract_unchecked_flows(context_map)
    entry_point_callees = _extract_entry_callees(context_map)
    flow_path_functions = _extract_flow_path_functions(flow_traces)
    entry_point_files = {
        ep.rsplit(":", 1)[0] for ep in entry_points if ":" in ep
    }

    binary_sink_callers: Set[str] = set()
    binary_surface_scores: Dict[str, float] = {}
    binary_boundary_fns: Set[str] = set()
    if binary_bridge is not None:
        binary_sink_callers = binary_bridge.sink_callers()
        binary_surface_scores = binary_bridge.surface_functions()
        binary_boundary_fns = binary_bridge.boundary_functions()

    scored = []
    for gap in gaps:
        key = f"{gap['file']}:{gap['name']}"
        score = 0

        is_entry_point = key in entry_points
        if is_entry_point:
            score += SCORE_ENTRY_POINT
        if key in sinks:
            score += SCORE_SINK
        if key in trust_boundaries:
            score += SCORE_TRUST_BOUNDARY
        if key in flow_path_functions or gap["file"] in flow_path_functions:
            score += SCORE_ON_FLOW_PATH
        if key in entry_point_callees:
            score += SCORE_CALLEE_OF_ENTRY
        if key in unchecked_flows:
            score += SCORE_UNCHECKED_FLOW
        if gap["file"] in entry_point_files:
            score += SCORE_FILE_HAS_ENTRY_POINT

        if tool_coverage is not None:
            file_tools = tool_coverage.get(gap["file"], set())
            if not file_tools:
                score += SCORE_NO_TOOL_COVERAGE
            elif len(file_tools) == 1:
                score += SCORE_PARTIAL_TOOL_COVERAGE

        if tool_failures and gap["file"] in tool_failures:
            score += SCORE_TOOL_FAILED

        if fuzz_coverage is not None and gap["file"] not in fuzz_coverage:
            score += SCORE_NOT_FUZZED

        visibility = (gap.get("metadata") or {}).get("visibility", "")
        if visibility in _EXPORTED_VISIBILITY:
            score += SCORE_EXPORTED

        if new_functions and key in new_functions:
            score += SCORE_NEW_CODE

        if threat_model:
            score += _threat_model_boost(gap, threat_model)

        if open_constraint_keys and key in open_constraint_keys:
            score += SCORE_OPEN_CONSTRAINT

        if strategy_weights:
            strategies = gap.get("strategies", [])
            if strategies:
                max_weight = max(
                    strategy_weights.get(s, 1.0) for s in strategies
                )
                boost = int((max_weight - 1.0) * SCORE_STRATEGY_MAX_BOOST)
                score += max(-SCORE_STRATEGY_MAX_BOOST, min(SCORE_STRATEGY_MAX_BOOST, boost))

        func_name = gap.get("name", "")
        if key in binary_sink_callers or func_name in binary_sink_callers:
            score += SCORE_BINARY_SINK
        if key in binary_surface_scores or func_name in binary_surface_scores:
            score += SCORE_BINARY_SURFACE
        if key in binary_boundary_fns or func_name in binary_boundary_fns:
            score += SCORE_PARSER_BOUNDARY

        sloc = gap.get("sloc", 0)
        if sloc >= _LARGE_SLOC:
            score += SCORE_LARGE_INTERNAL
        elif sloc >= _COMPLEX_SLOC:
            score += SCORE_COMPLEX
        elif sloc >= _MODERATE_SLOC:
            score += SCORE_MODERATE

        gap_with_score = {**gap, "priority_score": score}
        scored.append(gap_with_score)

    scored.sort(key=lambda g: (
        g["priority"],
        -g["priority_score"],
        -g.get("sloc", 0),
        g["file"],
        g["name"],
    ))
    return scored


def load_tool_coverage(run_dirs: List[Path]) -> Dict[str, Set[str]]:
    """Build a file→tools mapping from coverage run directories.

    Uses file_level_view() which returns {tool: {files: [...]}} and
    inverts it to {file: {tool1, tool2, ...}}.
    """
    result: Dict[str, Set[str]] = {}
    try:
        from core.coverage.store_summary import file_level_view
        view = file_level_view(run_dirs)
        for tool_name, tool_info in view.get("tools", {}).items():
            for file_path in tool_info.get("files", []):
                result.setdefault(file_path, set()).add(tool_name)
    except Exception:
        logger.debug("tool coverage loading failed", exc_info=True)
    return result


def load_tool_failures(run_dirs: List[Path]) -> Set[str]:
    """Identify files where a tool attempted to scan but failed."""
    failures: Set[str] = set()
    for run_dir in run_dirs:
        for cov_file in run_dir.glob("coverage-*.json"):
            try:
                with open(cov_file, encoding="utf-8") as f:
                    data = json.load(f)
                for fp in data.get("files_failed", []):
                    failures.add(fp)
            except (json.JSONDecodeError, OSError):
                continue
    return failures


def load_fuzz_coverage(run_dirs: List[Path]) -> Optional[Set[str]]:
    """Load files examined by fuzzing from coverage-fuzz.json."""
    fuzzed: Set[str] = set()
    found = False
    for run_dir in run_dirs:
        fuzz_path = run_dir / "coverage-fuzz.json"
        if not fuzz_path.exists():
            continue
        found = True
        try:
            with open(fuzz_path, encoding="utf-8") as f:
                data = json.load(f)
            for fp in data.get("files_examined", []):
                fuzzed.add(fp)
        except (json.JSONDecodeError, OSError):
            continue
    return fuzzed if found else None


def load_new_functions(
    out_dir: Path,
    checklist: Dict[str, Any],
) -> Set[str]:
    """Identify new/modified functions from inventory diff.

    Reads inventory-diff.json (produced by compare_inventories) and
    joins the affected files with the checklist to get function-level
    keys in file:function format.
    """
    diff_path = out_dir / "inventory-diff.json"
    if not diff_path.exists():
        return set()
    try:
        with open(diff_path, encoding="utf-8") as f:
            diff = json.load(f)
    except (json.JSONDecodeError, OSError):
        return set()

    affected_files = set(diff.get("added", []))
    affected_files.update(diff.get("modified", []))

    if not affected_files:
        return set()

    new_fns: Set[str] = set()
    for file_info in checklist.get("files", []):
        file_path = file_info.get("path", "")
        if file_path in affected_files:
            for item in file_info.get("items", file_info.get("functions", [])):
                name = item.get("name", "")
                if name:
                    new_fns.add(f"{file_path}:{name}")
    return new_fns


def detect_widely_used(
    checklist: Dict[str, Any],
    *,
    threshold: int = 20,
) -> Set[str]:
    """Identify widely-used functions (many consumers).

    Functions with >= threshold callers are likely correct themselves;
    the bug is in a consumer. Returns file:function keys.
    Uses the callers_of() API from core.analysis.reachability.
    """
    try:
        from core.analysis.reachability import callers_of, InternalFunction
    except ImportError:
        return set()

    widely_used: Set[str] = set()
    _caller_count_cache: Dict[str, int] = {}
    files_data = checklist.get("files", {})
    if isinstance(files_data, list):
        file_iter = ((f["path"], f.get("items", [])) for f in files_data if isinstance(f, dict))
    elif isinstance(files_data, dict):
        file_iter = (
            (k, v.get("items", []) if isinstance(v, dict) else v)
            for k, v in files_data.items()
        )
    else:
        return widely_used
    for file_path, items in file_iter:
        for item in items:
            name = item.get("name", "")
            if not name:
                continue
            cache_key = f"{file_path}:{name}"
            count = _caller_count_cache.get(cache_key)
            if count is None:
                line = item.get("line_start", 0) or 0
                try:
                    target = InternalFunction(
                        file_path=file_path, name=name, line=line,
                    )
                    r = callers_of(checklist, target)
                    count = len(r.all_callers)
                except Exception:
                    logger.debug(
                        "callers_of failed for %s:%s", file_path, name,
                        exc_info=True,
                    )
                    count = 0
                _caller_count_cache[cache_key] = count
            if count >= threshold:
                widely_used.add(cache_key)
    return widely_used


def group_by_subsystem(
    gaps: List[Dict[str, Any]],
    *,
    depth: int = 1,
) -> Dict[str, List[Dict[str, Any]]]:
    """Group gaps by directory (subsystem).

    Groups functions by their file's parent directory at the given depth.
    depth=1 means "top-level directory" (e.g. src/, lib/, kernel/).
    depth=2 means "second-level" (e.g. kernel/ipc/, net/ipv4/).

    Within each group, functions retain their existing sort order.
    This enables the orchestrator to build per-subsystem context
    before reviewing individual functions within that subsystem.
    """
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for gap in gaps:
        parts = Path(gap["file"]).parts
        if len(parts) > depth:
            subsystem = str(Path(*parts[:depth]))
        elif parts:
            subsystem = str(Path(*parts[:-1])) if len(parts) > 1 else "."
        else:
            subsystem = "."
        groups[subsystem].append(gap)
    return dict(groups)


def load_flow_traces(out_dir: Path) -> List[Dict[str, Any]]:
    """Load all flow-trace-*.json files from the output directory."""
    traces = []
    for path in sorted(out_dir.glob("flow-trace-*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                traces.append(json.load(f))
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("skipping %s: %s", path, exc)
    return traces


def _extract_unchecked_flows(
    context_map: Optional[Dict[str, Any]],
) -> Set[str]:
    if not context_map:
        return set()

    ep_index: Dict[str, Dict[str, Any]] = {}
    for ep in context_map.get("entry_points", []):
        ep_id = ep.get("id", "")
        if ep_id:
            ep_index[ep_id] = ep

    sink_index: Dict[str, Dict[str, Any]] = {}
    for sd in context_map.get("sink_details", []):
        sd_id = sd.get("id", "")
        if sd_id:
            sink_index[sd_id] = sd

    result = set()
    for flow in context_map.get("unchecked_flows", []):
        for loc in ("source", "sink", "entry_point"):
            val = flow.get(loc)
            if val is None:
                continue
            if isinstance(val, dict):
                key = f"{val.get('file', '')}:{val.get('name', '')}"
                if key != ":":
                    result.add(key)
            elif isinstance(val, str):
                ref = ep_index.get(val) or sink_index.get(val)
                if ref:
                    key = f"{ref.get('file', '')}:{ref.get('name', '')}"
                    if key != ":":
                        result.add(key)
    return result


def _extract_entry_callees(
    context_map: Optional[Dict[str, Any]],
    *,
    max_depth: int = 2,
) -> Set[str]:
    """Functions reachable from entry points within *max_depth* call hops."""
    if not context_map:
        return set()

    entry_keys = {
        f"{ep.get('file', '')}:{ep.get('name', '')}"
        for ep in context_map.get("entry_points", [])
    }

    result: Set[str] = set()
    for ep in context_map.get("entry_points", []):
        for callee in ep.get("callees", []):
            key = f"{callee.get('file', '')}:{callee.get('name', '')}"
            if key != ":":
                result.add(key)

    caller_to_callees: Dict[str, List[str]] = defaultdict(list)
    for edge in context_map.get("call_edges", []):
        caller_key = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
        callee_key = f"{edge.get('callee_file', edge.get('caller_file', ''))}:{edge.get('callee', '')}"
        if caller_key != ":" and callee_key != ":":
            caller_to_callees[caller_key].append(callee_key)

    if caller_to_callees:
        frontier = set(entry_keys)
        for _ in range(max_depth):
            next_frontier: Set[str] = set()
            for node in frontier:
                for callee_key in caller_to_callees.get(node, ()):
                    if callee_key not in entry_keys and callee_key not in result:
                        result.add(callee_key)
                        next_frontier.add(callee_key)
            if not next_frontier:
                break
            frontier = next_frontier

    return result


def _extract_flow_path_functions(
    flow_traces: Optional[List[Dict[str, Any]]],
) -> Set[str]:
    """Functions that appear on any traced flow path.

    Flow trace steps use "definition": "file:line" format. We extract
    the file path and match against gap keys (file:function). For steps
    that carry "file"/"function" keys directly, those are used instead.
    """
    if not flow_traces:
        return set()
    result = set()
    for trace in flow_traces:
        for step in trace.get("steps", trace.get("hops", [])):
            file = step.get("file", "")
            func = step.get("function", "")
            if not file and not func:
                defn = step.get("definition", "")
                if ":" in defn:
                    file = defn.rsplit(":", 1)[0]
            if file:
                result.add(file)
                if func:
                    result.add(f"{file}:{func}")
    return result


def _threat_model_boost(
    gap: Dict[str, Any],
    threat_model: Dict[str, Any],
) -> int:
    """Score boost when a gap matches operator-specified threat model focus."""
    focus_cwes = threat_model.get("focus_cwes")
    focus_areas = threat_model.get("focus_areas")
    if not focus_cwes and not focus_areas:
        return 0

    boost = 0
    gap_cwe = (gap.get("metadata") or {}).get("cwe", "")

    if focus_cwes and gap_cwe:
        if isinstance(focus_cwes, (list, set)):
            if gap_cwe in focus_cwes:
                boost += SCORE_THREAT_MODEL_FOCUS
        elif isinstance(focus_cwes, str) and gap_cwe == focus_cwes:
            boost += SCORE_THREAT_MODEL_FOCUS

    if focus_areas and isinstance(focus_areas, (list, set)):
        file_path = gap.get("file", "")
        for area in focus_areas:
            if isinstance(area, str) and file_path.startswith(area):
                boost += SCORE_THREAT_MODEL_FOCUS
                break

    return boost
