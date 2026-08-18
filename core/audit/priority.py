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
  +6   Parse/decode-shaped (byte-buffer signature + cursor walk /
       parser-API call — core.audit.parser_shape, structural/learned)
  +4   Dense length/size arithmetic (bounds-bug substrate)
  +4   Complex function (≥80 SLOC)
  +3   Callee of an entry point (1-hop from attack surface)
  +2   Dense error paths (validation-ordering substrate)
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
from collections import defaultdict
from pathlib import Path
from typing import Any

from ._util import extract_context_map_set
from .parser_shape import (
    ERROR_PATH_DENSITY_FLOOR,
    ERROR_PATH_SITES_FLOOR,
    LENGTH_ARITH_DENSITY_FLOOR,
    LENGTH_ARITH_SITES_FLOOR,
)

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
SCORE_PRIOR_SCAN_HIT = 3
SCORE_FUZZ_UNREACHED = 3
SCORE_FUZZ_REACHED_CLEAN = -1
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
# Structural parse/decode-shape components (core.audit.parser_shape,
# annotated onto gaps by compute_gaps). External-format decoders and
# their bounds arithmetic are where the review yield is — receipts:
# scoped-audit runs whose slots went to the thin exported siblings of
# the actual byte-walking workhorse.
SCORE_PARSER_SHAPED = 6
SCORE_LENGTH_ARITH = 4
SCORE_ERROR_PATHS = 2
SCORE_VALIDATE_CONFIRMED = 6
SCORE_VALIDATE_RULED_OUT = -3
SCORE_BINARY_ABSENT = -10

_COMPLEX_SLOC = 80
_MODERATE_SLOC = 30
_LARGE_SLOC = 200

# "Substantial coverage" threshold for the mild reached-crash-free
# demotion — mirrors gaps._FUZZ_HEAVY_ITERATIONS: below this a clean
# fuzz record says little.
FUZZ_SUBSTANTIAL_ITERATIONS = 10_000

_EXPORTED_VISIBILITY = frozenset({"extern", "exported", "public"})


def score_functions(
    gaps: list[dict[str, Any]],
    *,
    context_map: dict[str, Any] | None = None,
    flow_traces: list[dict[str, Any]] | None = None,
    tool_coverage: dict[str, set[str]] | None = None,
    tool_failures: set[str] | None = None,
    fuzz_coverage: set[str] | None = None,
    fuzz_function_coverage: dict[str, Any] | None = None,
    prior_scan_hit_keys: set[str] | None = None,
    new_functions: set[str] | None = None,
    threat_model: dict[str, Any] | None = None,
    open_constraint_keys: set[str] | None = None,
    strategy_weights: dict[str, float] | None = None,
    binary_bridge: Any | None = None,
    validate_confirmed_keys: set[str] | None = None,
    validate_ruled_out_keys: set[str] | None = None,
    binary_absent_keys: set[str] | None = None,
) -> list[dict[str, Any]]:
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
        fuzz_function_coverage: Per-function coverage-fuzz.json document
            (``files.{path}.functions.{name}`` records with ``reached``,
            ``iterations``, ``crashes``). Functions the fuzzer never
            reached get SCORE_FUZZ_UNREACHED; functions reached with
            substantial iterations and zero crashes get the mild
            SCORE_FUZZ_REACHED_CLEAN demotion.
        prior_scan_hit_keys: file:function keys with SARIF hits from a
            prior sibling scan run. Gets SCORE_PRIOR_SCAN_HIT — a
            scanner already flagged something here and no reviewer has
            looked yet.
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
        validate_confirmed_keys: file:function keys a prior /validate
            run confirmed as exploitable/confirmed — variant-dense
            regions, boosted with SCORE_VALIDATE_CONFIRMED.
        validate_ruled_out_keys: file:function keys a prior /validate
            run ruled out with strong receipts on unchanged source.
            Mildly deprioritised (SCORE_VALIDATE_RULED_OUT) — never
            skipped; a fresh hypothesis may differ in mechanism.
        binary_absent_keys: file:function keys the binary oracle says
            are absent from every analysed binary (full-DWARF tier,
            suppression-earning). Hard-deprioritised with
            SCORE_BINARY_ABSENT so live functions win budget slots;
            the triage classifier separately skips them.

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

    binary_sink_callers: set[str] = set()
    binary_surface_scores: dict[str, float] = {}
    binary_boundary_fns: set[str] = set()
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

        if fuzz_function_coverage:
            entry = _fuzz_function_entry(
                fuzz_function_coverage, gap["file"], gap["name"],
            )
            if entry is not None:
                if not entry.get("reached", True):
                    # Fuzzing examined the file but never exercised
                    # this function — dynamic analysis can't see it,
                    # so audit review should.
                    score += SCORE_FUZZ_UNREACHED
                elif (
                    entry.get("iterations", 0)
                    >= FUZZ_SUBSTANTIAL_ITERATIONS
                    and entry.get("crashes", 0) == 0
                ):
                    # Exercised a lot, never crashed: mild demotion
                    # only — fuzzing finds shallow bugs, not logic
                    # ones.
                    score += SCORE_FUZZ_REACHED_CLEAN

        if prior_scan_hit_keys and key in prior_scan_hit_keys:
            score += SCORE_PRIOR_SCAN_HIT

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

        if validate_confirmed_keys and key in validate_confirmed_keys:
            score += SCORE_VALIDATE_CONFIRMED
        elif validate_ruled_out_keys and key in validate_ruled_out_keys:
            score += SCORE_VALIDATE_RULED_OUT

        if binary_absent_keys and key in binary_absent_keys:
            score += SCORE_BINARY_ABSENT

        func_name = gap.get("name", "")
        if key in binary_sink_callers or func_name in binary_sink_callers:
            score += SCORE_BINARY_SINK
        if key in binary_surface_scores or func_name in binary_surface_scores:
            score += SCORE_BINARY_SURFACE
        if key in binary_boundary_fns or func_name in binary_boundary_fns:
            score += SCORE_PARSER_BOUNDARY

        # Structural parse/decode-shape components. Density floors
        # live in core.audit.parser_shape so the classifier and the
        # scorer can't drift apart.
        shape = gap.get("parser_shape") or {}
        if shape.get("parser_shaped"):
            score += SCORE_PARSER_SHAPED
        if (
            shape.get("length_arith_sites", 0) >= LENGTH_ARITH_SITES_FLOOR
            and shape.get("length_arith_density", 0.0)
            >= LENGTH_ARITH_DENSITY_FLOOR
        ):
            score += SCORE_LENGTH_ARITH
        if (
            shape.get("error_path_sites", 0) >= ERROR_PATH_SITES_FLOOR
            and shape.get("error_path_density", 0.0)
            >= ERROR_PATH_DENSITY_FLOOR
        ):
            score += SCORE_ERROR_PATHS

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


def _fuzz_function_entry(
    fuzz_data: dict[str, Any],
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    """Per-function record lookup (same shapes as loaders.fuzz_coverage_for)."""
    flat = fuzz_data.get(f"{file_path}:{function_name}")
    if isinstance(flat, dict):
        return flat
    file_data = fuzz_data.get("files", {}).get(file_path, {})
    entry = file_data.get("functions", {}).get(function_name)
    return entry if isinstance(entry, dict) else None


def load_tool_coverage(run_dirs: list[Path]) -> dict[str, set[str]]:
    """Build a file→tools mapping from coverage run directories.

    Uses file_level_view() which returns {tool: {files: [...]}} and
    inverts it to {file: {tool1, tool2, ...}}.
    """
    result: dict[str, set[str]] = {}
    try:
        from core.coverage.store_summary import file_level_view
        view = file_level_view(run_dirs)
        for tool_name, tool_info in view.get("tools", {}).items():
            for file_path in tool_info.get("files", []):
                result.setdefault(file_path, set()).add(tool_name)
    except Exception:
        logger.debug("tool coverage loading failed", exc_info=True)
    return result


def load_tool_failures(run_dirs: list[Path]) -> set[str]:
    """Identify files where a tool attempted to scan but failed."""
    failures: set[str] = set()
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


def load_fuzz_coverage(run_dirs: list[Path]) -> set[str] | None:
    """Load files examined by fuzzing from coverage-fuzz.json."""
    fuzzed: set[str] = set()
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
    checklist: dict[str, Any],
) -> set[str]:
    """Identify new/modified functions from inventory diff.

    Reads inventory-diff.json. When the diff carries function-level
    keys (``functions_added`` / ``functions_changed``, hash-based —
    written by the inventory builder or ``ensure_inventory_diff``),
    those are used directly. Legacy file-level diffs fall back to
    joining the affected files with the checklist, marking every
    function in a changed file.
    """
    diff_path = out_dir / "inventory-diff.json"
    if not diff_path.exists():
        return set()
    try:
        with open(diff_path, encoding="utf-8") as f:
            diff = json.load(f)
    except (json.JSONDecodeError, OSError):
        return set()

    if "functions_added" in diff or "functions_changed" in diff:
        return (set(diff.get("functions_added") or [])
                | set(diff.get("functions_changed") or []))

    affected_files = set(diff.get("added", []))
    affected_files.update(diff.get("modified", []))

    if not affected_files:
        return set()

    new_fns: set[str] = set()
    for file_info in checklist.get("files", []):
        file_path = file_info.get("path", "")
        if file_path in affected_files:
            for item in file_info.get("items", file_info.get("functions", [])):
                name = item.get("name", "")
                if name:
                    new_fns.add(f"{file_path}:{name}")
    return new_fns


def _latest_sibling_checklist(
    out_dir: Path, target_path: Path | None,
) -> dict[str, Any] | None:
    """The most recent sibling run's checklist.json, or None."""
    try:
        from .joern_backend import sibling_run_dirs
        dirs = sibling_run_dirs(out_dir, target_path=target_path)
    except Exception:
        logger.debug("sibling run discovery failed", exc_info=True)
        return None
    best: Path | None = None
    best_mtime = -1.0
    for d in dirs:
        p = d / "checklist.json"
        try:
            mtime = p.stat().st_mtime
        except OSError:
            continue
        if mtime > best_mtime:
            best, best_mtime = p, mtime
    if best is None:
        return None
    try:
        with open(best, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def ensure_inventory_diff(
    out_dir: Path,
    checklist: dict[str, Any],
    *,
    target_path: Path | None = None,
) -> set[str]:
    """Materialise ``inventory-diff.json`` for this run and return the
    new/changed function keys.

    The inventory builder writes the diff when it rebuilds in a
    directory that already holds a previous checklist; a fresh run
    directory has no previous checklist, so the production diff was
    never emitted and the new-code priority signal stayed dark. When
    the file is absent, diff the current checklist against the most
    recent sibling run's checklist (function-level, span-hash based)
    and persist the result so downstream loaders — gap computation and
    ``score_functions`` — see one consistent artifact.

    Best-effort: no discoverable previous inventory → empty set.
    """
    out_dir = Path(out_dir)
    diff_path = out_dir / "inventory-diff.json"
    if not diff_path.exists():
        previous = _latest_sibling_checklist(out_dir, target_path)
        if previous is None:
            return set()
        try:
            from core.inventory.diff import (
                compare_inventories,
                function_level_diff,
            )
            payload: dict[str, Any] = {
                "added": [], "removed": [], "modified": [],
                "functions_added": [], "functions_changed": [],
            }
            file_diff = compare_inventories(previous, checklist)
            if file_diff is not None:
                for k in ("added", "removed", "modified"):
                    payload[k] = list(file_diff.get(k) or [])
                payload.update(function_level_diff(previous, checklist))
            diff_path.write_text(json.dumps(payload, indent=2),
                                 encoding="utf-8")
        except Exception:
            logger.debug("inventory-diff materialisation failed",
                         exc_info=True)
            return set()
    return load_new_functions(out_dir, checklist)


def detect_widely_used(
    checklist: dict[str, Any],
    *,
    threshold: int = 20,
) -> set[str]:
    """Identify widely-used functions (many consumers).

    Functions with >= threshold callers are likely correct themselves;
    the bug is in a consumer. Returns file:function keys.
    Uses the callers_of() API from core.analysis.reachability.
    """
    try:
        from core.analysis.reachability import InternalFunction, callers_of
    except ImportError:
        return set()

    widely_used: set[str] = set()
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
    # No memoisation: each (file, name) checklist item is visited
    # exactly once per call, so a per-call cache could never hit —
    # and a duplicate name within one file would silently reuse the
    # first definition's count.
    for file_path, items in file_iter:
        for item in items:
            name = item.get("name", "")
            if not name:
                continue
            key = f"{file_path}:{name}"
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
            if count >= threshold:
                widely_used.add(key)
    return widely_used


def group_by_subsystem(
    gaps: list[dict[str, Any]],
    *,
    depth: int = 1,
) -> dict[str, list[dict[str, Any]]]:
    """Group gaps by directory (subsystem).

    Groups functions by their file's parent directory at the given depth.
    depth=1 means "top-level directory" (e.g. src/, lib/, kernel/).
    depth=2 means "second-level" (e.g. kernel/ipc/, net/ipv4/).

    Within each group, functions retain their existing sort order.
    This enables the orchestrator to build per-subsystem context
    before reviewing individual functions within that subsystem.
    """
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
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


def load_flow_traces(out_dir: Path) -> list[dict[str, Any]]:
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
    context_map: dict[str, Any] | None,
) -> set[str]:
    if not context_map:
        return set()

    ep_index: dict[str, dict[str, Any]] = {}
    for ep in context_map.get("entry_points", []):
        ep_id = ep.get("id", "")
        if ep_id:
            ep_index[ep_id] = ep

    sink_index: dict[str, dict[str, Any]] = {}
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
    context_map: dict[str, Any] | None,
    *,
    max_depth: int = 2,
) -> set[str]:
    """Functions reachable from entry points within *max_depth* call hops."""
    if not context_map:
        return set()

    entry_keys = {
        f"{ep.get('file', '')}:{ep.get('name', '')}"
        for ep in context_map.get("entry_points", [])
    }

    result: set[str] = set()
    for ep in context_map.get("entry_points", []):
        for callee in ep.get("callees", []):
            key = f"{callee.get('file', '')}:{callee.get('name', '')}"
            # Same exclusion as the BFS below: an entry point listed
            # among another entry's callees already scores
            # SCORE_ENTRY_POINT and must not double-count.
            if key != ":" and key not in entry_keys:
                result.add(key)

    caller_to_callees: dict[str, list[str]] = defaultdict(list)
    for edge in context_map.get("call_edges", []):
        caller_key = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
        callee_key = f"{edge.get('callee_file', edge.get('caller_file', ''))}:{edge.get('callee', '')}"
        if caller_key != ":" and callee_key != ":":
            caller_to_callees[caller_key].append(callee_key)

    if caller_to_callees:
        frontier = set(entry_keys)
        for _ in range(max_depth):
            next_frontier: set[str] = set()
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
    flow_traces: list[dict[str, Any]] | None,
) -> set[str]:
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
    gap: dict[str, Any],
    threat_model: dict[str, Any],
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
