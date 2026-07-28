"""Gap computation from inventory + coverage records.

A function is a *gap* when it has no entry in any coverage record,
no finding, and no ``checked_by`` label. Stale functions (source hash
mismatch since last annotation) are treated as gaps that carry their
old annotation as context for re-review.

Gaps are sorted by priority:
  1. Functions in files with NO tool coverage (highest)
  2. Functions in files with partial tool coverage
  3. Stale annotations (source changed since review)
  4. Functions in fully-covered files (lowest)
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .strategy import strategies_from_item
from ._util import extract_context_map_set

logger = logging.getLogger(__name__)

PRIORITY_ENTRY_POINT = -1
PRIORITY_NO_TOOL_COVERAGE = 0
PRIORITY_PARTIAL_TOOL_COVERAGE = 1
PRIORITY_STALE = 2
PRIORITY_FULLY_COVERED = 3
PRIORITY_DEAD_CODE = 4

_TRIVIAL_SLOC = 5
_SMALL_ENTRY_SLOC = 20
_LARGE_SLOC = 200
_REVIEWABLE_KINDS = frozenset({"function", "method", ""})


def compute_gaps(
    checklist: Dict[str, Any],
    coverage_records: List[Dict[str, Any]],
    *,
    annotations_dir: Optional[Path] = None,
    context_map: Optional[Dict[str, Any]] = None,
    strategy_filter: Optional[str] = None,
    budget: Optional[int] = None,
    scope: Optional[str] = None,
    fuzz_coverage: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Compute the list of unreviewed functions.

    Args:
        checklist: Parsed checklist.json.
        coverage_records: All coverage records from the run/project dir.
        annotations_dir: If provided, check for stale annotations
            (hash mismatch).
        context_map: If provided, used for sink-reachability-based
            priority boosting and strategy selection.
        strategy_filter: If set, only include functions whose inferred
            strategies include this strategy name.
        budget: Maximum number of gaps to return.
        scope: If set, only include functions whose file path starts
            with this prefix (e.g. "ipc/" to audit only the ipc
            subsystem). Annotations and coverage still write to the
            project-level output dir.
        fuzz_coverage: If provided, functions with substantial fuzz
            coverage (many iterations, zero crashes) are deprioritized
            but NOT skipped.

    Returns:
        List of gap dicts sorted by priority, each containing:
        - file, name, line_start, line_end, priority, strategies,
          is_stale, old_annotation (if stale)
    """
    covered_functions = _build_covered_set(coverage_records)
    file_tool_coverage = _build_file_tool_coverage(coverage_records)
    entry_point_sinks = _build_sink_reachability(context_map)
    entry_point_set = extract_context_map_set(context_map, "entry_points")
    if not entry_point_set:
        entry_point_set = _derive_entry_points(checklist)

    effective_scope = scope
    if scope:
        target_path = checklist.get("target_path", "")
        if target_path:
            normalised = target_path.rstrip("/")
            scope_norm = scope.rstrip("/")
            if normalised.endswith("/" + scope_norm) or normalised == scope_norm:
                effective_scope = None

    gaps: List[Dict[str, Any]] = []

    for file_info in checklist.get("files", []):
        file_path = file_info.get("path", "")

        if effective_scope and not file_path.startswith(effective_scope):
            continue
        items = file_info.get("items", file_info.get("functions", []))

        file_coverage = file_tool_coverage.get(file_path, set())

        for item in items:
            name = item.get("name", "")
            item_kind = item.get("kind", "")

            if item_kind not in _REVIEWABLE_KINDS:
                continue

            func_key = f"{file_path}:{name}"

            if func_key in covered_functions:
                continue

            if item.get("checked_by"):
                continue

            line_start = item.get("line_start", 0)
            line_end = item.get("line_end")
            sloc = (line_end - line_start + 1) if line_end else 0

            reachable_sinks = entry_point_sinks.get(
                f"{file_path}:{name}"
            )

            strategies = strategies_from_item(
                item, file_path,
                reachable_sinks=reachable_sinks,
            )

            if strategy_filter and strategy_filter not in strategies:
                continue

            is_entry_point = func_key in entry_point_set
            item_kind = item.get("kind", "")
            metadata = item.get("metadata") or {}
            visibility = metadata.get("visibility", "")

            bo = metadata.get("binary_oracle")
            binary_absent = (
                bo is not None
                and bo.get("classification") == "absent"
            )

            fuzz_info = _fuzz_info_for(fuzz_coverage, file_path, name)

            priority = _compute_priority(
                file_coverage=file_coverage,
                reachable_sinks=reachable_sinks,
                sloc=sloc,
                is_entry_point=is_entry_point,
                item_kind=item_kind,
                visibility=visibility,
                binary_absent=binary_absent,
                fuzz_iterations=fuzz_info[0],
                fuzz_crashes=fuzz_info[1],
            )

            gap = {
                "file": file_path,
                "name": name,
                "line_start": line_start,
                "line_end": line_end,
                "priority": priority,
                "strategies": sorted(strategies),
                "is_stale": False,
                "sloc": sloc,
            }

            if item.get("lexical_dead"):
                gap["lexical_dead"] = True
            file_abort = file_info.get("module_aborts_on_load")
            if isinstance(file_abort, dict):
                abort_line = file_abort.get("line", 0)
                if abort_line and line_start >= abort_line:
                    gap["module_aborts_on_load"] = True
            if isinstance(file_info.get("build_excluded"), dict):
                gap["build_excluded"] = True

            if gap.get("lexical_dead") or gap.get("module_aborts_on_load") or gap.get("build_excluded"):
                gap["dead"] = True

            if reachable_sinks:
                gap["reachable_sinks"] = reachable_sinks

            gaps.append(gap)

    gaps.sort(key=lambda g: (g["priority"], -g.get("sloc", 0)))

    if budget is not None and budget > 0:
        gaps = gaps[:budget]

    return gaps


def load_checklist(out_dir: Path) -> Dict[str, Any]:
    """Load checklist.json from the output directory."""
    path = out_dir / "checklist.json"
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError:
        logger.error("malformed JSON in %s", path)
        return {}


def gap_for_site(
    checklist: Dict[str, Any],
    file_path: str,
    line: int,
    *,
    priority: int = 1,
) -> Optional[Dict[str, Any]]:
    """Build a reviewable gap for the function enclosing ``file_path:line``.

    Mechanical sweeps (Mode-2 checker synthesis, rule replay) report
    *sites* — a file and a line — not functions. The review loop needs
    the enclosing function, in the same shape ``compute_gaps`` emits, or
    downstream consumers that index gaps by ``name`` blow up.

    Returns None when no reviewable checklist function covers the line
    (generated code, a header, a match outside any function body). The
    caller should drop the site: without a function there is no context
    slice to review.
    """
    if not file_path or line <= 0:
        return None

    # Tolerate a malformed checklist rather than raising. This runs in
    # the synthesis second pass, after the main review loop but before
    # the run's state is flushed, so an exception here costs the run its
    # results. Fewer resolved gaps is the correct degradation.
    files = checklist.get("files") if isinstance(checklist, dict) else None
    if not isinstance(files, list):
        return None

    for file_info in files:
        if not isinstance(file_info, dict):
            continue
        if file_info.get("path") != file_path:
            continue

        raw_items = file_info.get("items")
        if raw_items is None:
            raw_items = file_info.get("functions")
        if not isinstance(raw_items, list):
            continue

        items = [
            it for it in raw_items
            if isinstance(it, dict)
            and it.get("kind", "") in _REVIEWABLE_KINDS
            and it.get("name")
            and isinstance(it.get("line_start"), int)
            and not isinstance(it.get("line_start"), bool)
        ]
        if not items:
            continue

        # Same two-phase resolution as
        # core.orchestration.understand_bridge._find_containing_function,
        # so a site resolves the same way whichever component asks.
        #
        # Strict: smallest containing span wins, so a nested function or
        # closure is attributed to the innermost match rather than to the
        # enclosing definition.
        best: Optional[Dict[str, Any]] = None
        best_span = None
        for item in items:
            line_start = item["line_start"]
            line_end = item.get("line_end")
            if not isinstance(line_end, int) or isinstance(line_end, bool):
                continue
            if not (line_start <= line <= line_end):
                continue
            span = line_end - line_start
            if best_span is None or span < best_span or (
                span == best_span and line_start > best["line_start"]
            ):
                best = dict(item)
                best_span = span

        # Fallback for inventories that record only the definition line:
        # closest preceding line_start, bounded by the NEXT definition.
        #
        # A trailing definition with no next start has no derivable upper
        # bound here — inventing one either truncates the function (so
        # review and hydration miss its tail) or over-claims lines that
        # belong to nothing. Those sites stay unresolved and are recorded
        # in the unresolved-hits artifact, which is honest rather than
        # quietly wrong.
        if best is None:
            starts = sorted({it["line_start"] for it in items})
            preceding = [s for s in starts if s <= line]
            if not preceding:
                continue
            chosen_start = preceding[-1]
            candidates = [
                it for it in items
                if it["line_start"] == chosen_start
                and it.get("line_end") is None
            ]
            later = [s for s in starts if s > chosen_start]
            if not candidates or not later:
                continue
            best = dict(candidates[0])
            best["line_end"] = later[0] - 1
            best["span_inferred"] = True

        gap = {
            "file": file_path,
            "name": best["name"],
            "line_start": best["line_start"],
            "line_end": best["line_end"],
            "priority": priority,
            "strategies": sorted(strategies_from_item(best, file_path)),
            "is_stale": False,
            "sloc": best["line_end"] - best["line_start"] + 1,
        }
        if best.get("span_inferred"):
            gap["span_inferred"] = True
        return gap

    return None


def load_context_map(out_dir: Path) -> Optional[Dict[str, Any]]:
    """Load context-map.json if present."""
    path = out_dir / "context-map.json"
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError:
        logger.error("malformed JSON in %s", path)
        return None


def write_gaps(gaps: List[Dict[str, Any]], out_dir: Path) -> Path:
    """Write gaps.json to the output directory."""
    path = out_dir / "gaps.json"
    fd, tmp = tempfile.mkstemp(dir=str(out_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"gaps": gaps, "count": len(gaps)}, f, indent=2)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def mark_checked(
    out_dir: Path,
    file_path: str,
    function_name: str,
    checked_by: List[str],
) -> None:
    """Write checked_by into the checklist so future runs skip this function."""
    cl_path = out_dir / "checklist.json"
    if not cl_path.exists():
        return
    try:
        with open(cl_path) as f:
            checklist = json.load(f)
    except json.JSONDecodeError:
        return

    for file_info in checklist.get("files", []):
        if file_info.get("path") != file_path:
            continue
        for item in file_info.get("items", file_info.get("functions", [])):
            if item.get("name") == function_name:
                existing = item.get("checked_by", [])
                merged = sorted(set(existing) | set(checked_by))
                item["checked_by"] = merged
                break
        break

    fd, tmp = tempfile.mkstemp(dir=str(cl_path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(checklist, f, indent=2)
        os.replace(tmp, str(cl_path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _build_covered_set(
    records: List[Dict[str, Any]],
) -> set:
    """Build set of file:function keys that have coverage."""
    covered = set()
    for record in records:
        for file_path, file_data in record.get("files", {}).items():
            for func_name in file_data.get("functions", {}):
                covered.add(f"{file_path}:{func_name}")
    return covered


def _build_file_tool_coverage(
    records: List[Dict[str, Any]],
) -> Dict[str, set]:
    """Map each file to the set of tools that covered it."""
    coverage: Dict[str, set] = {}
    for record in records:
        tool = record.get("tool", "unknown")
        for file_path in record.get("files", {}):
            coverage.setdefault(file_path, set()).add(tool)
        for file_path in record.get("files_examined", []):
            coverage.setdefault(file_path, set()).add(tool)
    return coverage


def _build_sink_reachability(
    context_map: Optional[Dict[str, Any]],
) -> Dict[str, List[str]]:
    """Extract file:name → reachable_sinks from all context map sources.

    Checks entry_points, the sinks array, and sink_discovery transitive_reach
    so that non-entry-point functions that reach dangerous targets are also
    prioritised.
    """
    if not context_map:
        return {}
    result: Dict[str, List[str]] = {}

    for ep in context_map.get("entry_points", []):
        sinks = ep.get("reachable_sinks")
        if sinks:
            key = f"{ep.get('file', '')}:{ep.get('name', '')}"
            result[key] = list(sinks)

    for sink in context_map.get("sinks", []):
        f = sink.get("file", "")
        fn = sink.get("function", "")
        target = sink.get("target", "")
        if f and fn and target:
            key = f"{f}:{fn}"
            result.setdefault(key, [])
            if target not in result[key]:
                result[key].append(target)

    sd = context_map.get("sink_discovery", {})
    for tr in sd.get("transitive_reach", []):
        f = tr.get("file", "")
        fn = tr.get("function", "")
        sinks = tr.get("reachable_sinks", [])
        if f and fn and sinks:
            key = f"{f}:{fn}"
            result.setdefault(key, [])
            for s in sinks:
                if s not in result[key]:
                    result[key].append(s)

    return result




def _derive_entry_points(checklist: Dict[str, Any]) -> set:
    """Derive entry points from checklist when no context map is available.

    Uses header_api (C/C++ public API from headers) when present,
    otherwise falls back to visibility-based heuristic.
    """
    header_api_raw = checklist.get("header_api")
    header_api = frozenset(header_api_raw) if header_api_raw else None

    entries = set()
    for file_info in checklist.get("files", []):
        file_path = file_info.get("path", "")
        lang = file_info.get("language", "")
        items = file_info.get("items", file_info.get("functions", []))

        for item in items:
            name = item.get("name", "")
            if not name:
                continue
            metadata = item.get("metadata") or {}
            visibility = metadata.get("visibility", "")

            if lang in ("c", "cpp"):
                if header_api is not None:
                    if name in header_api:
                        entries.add(f"{file_path}:{name}")
                elif visibility != "static":
                    entries.add(f"{file_path}:{name}")
            elif lang == "go" and name[:1].isupper():
                entries.add(f"{file_path}:{name}")
            elif lang == "rust" and visibility == "pub":
                entries.add(f"{file_path}:{name}")

    return entries


_FUZZ_HEAVY_ITERATIONS = 10_000


def _fuzz_info_for(
    fuzz_coverage: Optional[Dict[str, Any]],
    file_path: str,
    function_name: str,
) -> tuple:
    """Return (iterations, crashes) for a function, or (0, 0) if no data."""
    if not fuzz_coverage:
        return (0, 0)
    file_data = fuzz_coverage.get("files", {}).get(file_path, {})
    func_data = file_data.get("functions", {}).get(function_name)
    if not func_data:
        return (0, 0)
    return (func_data.get("iterations", 0), func_data.get("crashes", 0))


def _compute_priority(
    *,
    file_coverage: set,
    reachable_sinks: Optional[List[str]],
    sloc: int,
    is_entry_point: bool = False,
    item_kind: str = "",
    visibility: str = "",
    binary_absent: bool = False,
    fuzz_iterations: int = 0,
    fuzz_crashes: int = 0,
) -> int:
    """Assign priority (lower = higher priority).

    Order: entry points with sinks > entry points > sink-reachable >
    uncovered > partial > stale > fully covered > fuzz-heavy > dead.

    Fuzz coverage deprioritizes but never skips: a function with many
    iterations and zero crashes has been exercised by a harness already,
    so the LLM should focus elsewhere first. Functions with crashes get
    NO deprioritization — they're interesting.
    """
    if is_entry_point:
        if sloc <= _TRIVIAL_SLOC:
            return PRIORITY_NO_TOOL_COVERAGE
        if sloc <= _SMALL_ENTRY_SLOC:
            return PRIORITY_NO_TOOL_COVERAGE
        return PRIORITY_ENTRY_POINT

    if sloc >= _LARGE_SLOC:
        return PRIORITY_ENTRY_POINT

    if reachable_sinks:
        return PRIORITY_NO_TOOL_COVERAGE

    if binary_absent or item_kind == "interstitial":
        return PRIORITY_DEAD_CODE

    if not file_coverage:
        base = PRIORITY_NO_TOOL_COVERAGE
    elif len(file_coverage) < 2:
        base = PRIORITY_PARTIAL_TOOL_COVERAGE
    else:
        base = PRIORITY_FULLY_COVERED

    if sloc and sloc <= _TRIVIAL_SLOC:
        base = max(base, PRIORITY_FULLY_COVERED)

    if (
        fuzz_iterations >= _FUZZ_HEAVY_ITERATIONS
        and fuzz_crashes == 0
    ):
        base = max(base, PRIORITY_FULLY_COVERED)

    return base
