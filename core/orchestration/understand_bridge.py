"""Bridge between /understand output and /validate input.
This is the start of the full automation vision where our idea is that an analyst can run /understand to get a head start on mapping the 
attack surface and then seamlessly pick up that context in /validate without manual exports or imports.

Handles three things automatically so the analyst doesn't have to:

  1. Populate attack-surface.json from context-map.json, the schemas share the
     same required keys (sources/sinks/trust_boundaries), so this is a selective
     copy plus merge when the file already exists.

  2. Import flow-trace-*.json into attack-paths.json — steps[], proximity, and
     blockers[] are shared schema between trace and attack-paths, so traces slot
     straight in as starting paths for Stage B.

  3. Enrich checklist.json with priority markers, functions that appear as entry
     points or sinks in the context map are tagged high-priority so Stage B attacks
     the most important code first rather than working through a flat list.

Usage (from Stage 0 in /validate):

    from core.orchestration.understand_bridge import find_understand_output, load_understand_context, enrich_checklist

    understand_dir, stale_files = find_understand_output(validate_dir, target_path=target)
    if understand_dir:
        bridge = load_understand_context(understand_dir, validate_dir, stale_files)
        if bridge["context_map_loaded"]:
            enrich_checklist(checklist, bridge["context_map"], str(validate_dir))

The three-tier search in find_understand_output() covers:
  1. Shared --out directory (context-map.json co-located)
  2. Project sibling directories (same project, different run)
  3. Global out/ scan (match by checklist target_path — no project needed)
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.json import load_json, save_json
from core.security.log_sanitisation import escape_nonprintable

logger = logging.getLogger(__name__)

# Label used in attack-paths to mark entries imported from /understand traces.
# Stage B uses this to distinguish its own paths from pre-loaded ones.
TRACE_SOURCE_LABEL = "understand:trace"

# BVProfile name shorthands accepted on the optional ``path_profile`` field
# of a flow trace.  Mirrors the names accepted by ``raptor-smt-validate-path``
# so Stage E can pass the value through without translation.
_VALID_PROFILE_NAMES = frozenset({
    "uint8", "int8", "uint16", "int16",
    "uint32", "int32", "uint64", "int64",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def find_understand_output(
    validate_dir: Path,
    target_path: str = None,
) -> Tuple[Optional[Path], Set[str]]:
    """Find the best /understand output for a validate run.

    Three-tier search eliminates the need for --out alignment:

    1. **Local**: context-map.json already in validate_dir (shared --out case)
    2. **Project siblings**: sibling run dirs in the same project
    3. **Global out/**: scan out/ for understand runs matching the same target_path

    When multiple candidates exist across tiers 2+3, they are ranked by
    hash freshness first (files unchanged since understand ran) then by
    modification time. A stale candidate is only selected if no fresh one
    exists.

    Freshness is determined by hashing current files on disk and comparing
    against the understand run's checklist — not against the validate
    checklist, which may share a symlinked file in project mode.

    Args:
        validate_dir: The validate run's output directory.
        target_path: The target being validated (used for target-path match,
            global out/ search, and on-disk hash freshness checks).

    Returns:
        (path, stale_files) — path to the understand output directory and
        set of relative file paths whose hashes no longer match disk.
        Returns (None, set()) when no understand output is found.
        When tier 1 matches, returns (validate_dir, empty set) since
        co-located data is assumed fresh.
    """
    validate_dir = Path(validate_dir)
    empty: Set[str] = set()

    # Tier 1: context-map.json co-located (shared --out directory).
    # Staleness can't be checked here — the validate rebuild overwrites
    # the understand checklist before the bridge runs.  The caller
    # (validation helper) snapshots the pre-rebuild checklist and handles
    # tier 1 staleness separately.
    if (validate_dir / "context-map.json").exists():
        logger.debug("understand output: tier 1 (local) — %s", validate_dir)
        return validate_dir, empty

    # Collect candidates from tiers 2 and 3
    candidates = _collect_candidates(validate_dir, target_path)
    if not candidates:
        return None, empty

    # Rank: fresh hashes beat stale, then newest wins
    result = _rank_candidates(candidates, target_path)
    if result is None:
        return None, empty
    best_dir, stale_files = result
    logger.debug("understand output: selected %s", best_dir)
    return best_dir, stale_files


def _collect_candidates(
    validate_dir: Path, target_path: str = None,
) -> List[Path]:
    """Gather understand run directories from tiers 2 and 3."""
    seen: set = set()
    results: List[Path] = []

    # Tier 2: project sibling directories
    parent = validate_dir.parent  # e.g. out/projects/myapp/
    for d in _search_understand_dirs(parent, exclude=validate_dir,
                                     require_target=target_path):
        resolved = d.resolve()
        if resolved not in seen:
            seen.add(resolved)
            results.append(d)

    # Tier 3: global out/ search (only dirs matching target_path)
    if target_path:
        from core.config import RaptorConfig
        out_root = RaptorConfig.get_out_dir()
        for d in _search_understand_dirs(out_root, exclude=validate_dir,
                                         require_target=target_path):
            resolved = d.resolve()
            if resolved not in seen:
                seen.add(resolved)
                results.append(d)

    return results


def _rank_candidates(
    candidates: List[Path],
    target_path: str = None,
) -> Optional[Tuple[Path, Set[str]]]:
    """Pick the best candidate: fresh hashes > stale, then newest first.

    Freshness is checked by hashing the current files on disk under
    target_path and comparing against the understand run's checklist.
    This avoids the symlink problem where project-mode checklists
    share a single file and the validate rebuild overwrites understand
    hashes.

    Returns (path, stale_files) or None if candidates is empty.
    """
    if not candidates:
        return None

    if not target_path:
        # No target — can't hash on disk, just pick newest.
        # Use mtime_ns for sub-second resolution; directory name breaks ties.
        candidates.sort(key=lambda d: (d.stat().st_mtime_ns, d.name), reverse=True)
        return candidates[0], set()

    scored = []
    for d in candidates:
        u_checklist = load_json(d / "checklist.json")
        if not u_checklist:
            # No checklist — treat as fully stale (can't verify any file)
            scored.append((1, d.stat().st_mtime_ns, d, set()))
            continue
        u_hashes = _extract_hashes(u_checklist)
        stale = _find_stale_files(u_hashes, target_path)
        # fresh = 0 stale files → sort key 0 (best)
        scored.append((len(stale), d.stat().st_mtime_ns, d, stale))

    # Sort descending: fewest stale (negated), then newest mtime_ns, then
    # directory name (timestamp-based names sort chronologically).
    scored.sort(key=lambda t: (-t[0], t[1], t[2].name), reverse=True)
    best_stale_count, _, best_dir, best_stale_files = scored[0]

    if best_stale_count > 0:
        logger.warning(
            "understand_bridge: best candidate %s has %d stale file(s)"
            " — data for these files will be excluded: %s",
            best_dir.name, best_stale_count,
            ", ".join(escape_nonprintable(f) for f in sorted(best_stale_files)),
        )

    return best_dir, best_stale_files


def _extract_hashes(checklist: Dict[str, Any]) -> Dict[str, str]:
    """Build {relative_path: sha256} from a checklist."""
    return {
        f["path"]: f["sha256"]
        for f in checklist.get("files", [])
        if f.get("sha256")
    }


def _find_stale_files(
    understand_hashes: Dict[str, str],
    target_path: str,
) -> Set[str]:
    """Return relative paths whose on-disk SHA-256 differs from the understand checklist.

    Hashes the actual files under target_path rather than comparing against
    another checklist. This is immune to the project-mode symlink problem
    where both runs share one checklist.json file.
    """
    from core.hash import sha256_file

    target = Path(target_path)
    stale: Set[str] = set()
    for rel_path, u_hash in understand_hashes.items():
        full_path = target / rel_path
        if not full_path.is_file():
            # File deleted since understand ran
            stale.add(rel_path)
            continue
        disk_hash = sha256_file(full_path)
        if disk_hash != u_hash:
            stale.add(rel_path)
    return stale


def _search_understand_dirs(
    parent_dir: Path,
    exclude: Path = None,
    require_target: str = None,
) -> List[Path]:
    """Find understand run directories under parent_dir.

    Args:
        parent_dir: Directory to scan (e.g. project dir or out/).
        exclude: Directory to skip (typically the validate dir itself).
        require_target: If set, only return dirs whose checklist.json
            target_path resolves to this path.

    Returns:
        List of matching directories, sorted newest-first by mtime.
    """
    from core.run import infer_command_type

    parent_dir = Path(parent_dir)
    if not parent_dir.is_dir():
        return []

    target_resolved = (
        str(Path(require_target).resolve()) if require_target else None
    )

    results = []
    for d in parent_dir.iterdir():
        try:
            if not (d.is_dir()
                    and d != exclude
                    and not d.name.startswith((".", "_"))
                    and infer_command_type(d) == "understand"
                    and (d / "context-map.json").exists()):
                continue
        except OSError:
            continue  # broken symlinks, permission errors

        if target_resolved:
            from core.json import load_json
            checklist = load_json(d / "checklist.json")
            if not checklist:
                continue
            d_target = checklist.get("target_path", "")
            if not d_target or str(Path(d_target).resolve()) != target_resolved:
                continue

        results.append(d)

    results.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return results


def load_understand_context(
    understand_dir: Path,
    validate_dir: Path,
    stale_files: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    #Import /understand outputs as /validate starting state.
    understand_dir = Path(understand_dir)
    validate_dir = Path(validate_dir)
    validate_dir.mkdir(parents=True, exist_ok=True)
    if stale_files is None:
        stale_files = set()

    summary: Dict[str, Any] = {
        "understand_dir": str(understand_dir),
        "context_map_loaded": False,
        "stale_files_excluded": sorted(stale_files),
        "attack_surface": {
            "sources": 0,
            "sinks": 0,
            "trust_boundaries": 0,
            "gaps": 0,
            "unchecked_flows": 0,
        },
        "flow_traces": {
            "count": 0,
            "imported_as_paths": 0,
        },
        "context_map": {},
    }

    # --- Load context-map.json ---
    context_map = _load_context_map(understand_dir)
    if context_map is None:
        logger.warning("understand_bridge: no context-map.json found in %s", understand_dir)
        return summary

    # --- Normalise the context-map (path conventions, name backfill,
    #     hallucination warnings) BEFORE filtering so stale-file matching
    #     compares canonical paths. Otherwise an entry with `./foo.py`
    #     would survive a stale-files set containing the canonical
    #     `foo.py` and leak through. The validate dir's checklist is the
    #     ground truth for normalisation. ---
    validate_checklist = load_json(validate_dir / "checklist.json") or {}
    normalize_context_map(context_map, validate_checklist,
                          target_path=validate_checklist.get("target_path"))

    # --- Filter entries referencing stale files (now using normalised paths) ---
    filtered = _filter_context_map(context_map, stale_files)
    if filtered:
        logger.info("understand_bridge: excluded %d entries referencing stale files", filtered)

    summary["context_map_loaded"] = True
    summary["context_map"] = context_map

    # --- Populate attack-surface.json ---
    surface_stats = _merge_attack_surface(context_map, validate_dir, understand_dir)
    summary["attack_surface"] = surface_stats

    # --- Import flow-trace-*.json into attack-paths.json ---
    trace_stats = _import_flow_traces(understand_dir, validate_dir, stale_files)
    summary["flow_traces"] = trace_stats

    logger.info(
        "understand_bridge: loaded context map from %s — "
        "%d sources, %d sinks, %d trust boundaries, %d unchecked flows, "
        "%d trace(s) imported as attack paths",
        understand_dir,
        surface_stats["sources"],
        surface_stats["sinks"],
        surface_stats["trust_boundaries"],
        surface_stats["unchecked_flows"],
        trace_stats["imported_as_paths"],
    )

    return summary


def normalize_context_map(context_map: Dict[str, Any], checklist: Dict[str, Any],
                          target_path: Optional[str] = None) -> Dict[str, Any]:
    """Mechanically fix up an LLM-produced context-map using the checklist
    as ground truth.

    Mutates ``context_map`` in place; returns it for chaining. Does five
    deterministic passes that are safe to run multiple times (idempotent):

    1. **Path normalisation** on every ``file:`` field across entry_points,
       sink_details, boundary_details. Strips leading ``./``; converts
       absolute paths under ``target_path`` to relative-from-target. The
       bridge's downstream strict-equality match is sensitive to this.

    2. **Name backfill** on entry_points and sink_details: when the LLM
       emitted ``file`` + ``line`` but no ``name``, look up the function
       in the checklist whose line range contains that line and inject
       the function's name. Enables function-level enrichment instead of
       falling back to file-level (which over-marks unrelated helpers).

    3. **File-existence validation**: warns when a context-map entry
       references a file that doesn't appear in the checklist (LLM
       hallucination).

    4. **Line-in-file sanity**: warns when a referenced line exceeds the
       file's known length.

    5. **Cross-reference validation**: warns when ``unchecked_flows``
       references entry_point or sink IDs that don't exist in the
       respective lists.

    Returns the (mutated) context_map for caller convenience. Bails as a
    no-op if either input is missing or wrong-typed.
    """
    if not isinstance(context_map, dict):
        return context_map

    # Path normalisation and cross-ref validation don't need the checklist
    # — run them unconditionally so callers without an inventory still
    # benefit from those passes.
    _normalize_paths(context_map, target_path)
    _validate_cross_refs(context_map)

    if not isinstance(checklist, dict):
        # Backfill / hallucination warnings need the checklist as ground truth.
        return context_map

    files_by_path = {
        fi.get("path"): fi
        for fi in _list_at(checklist, "files")
        if isinstance(fi, dict) and fi.get("path")
    }
    _backfill_and_validate_locations(context_map, files_by_path)
    return context_map


# Top-level keys whose entries carry a (file, line) pair worth normalising.
_LOCATION_BEARING_SECTIONS = ("entry_points", "sink_details", "boundary_details")


def _list_at(d: Any, key: str) -> List[Any]:
    """Return d[key] if it's a list, else an empty list.

    Defensive guard for the many `for x in context_map.get(field) or []`
    sites: `or []` falls back to `[]` only when the value is *falsy*, so
    a truthy non-list (string, int, dict) would still hit `for x in 42`
    and raise TypeError. Use this helper at every iteration site.
    """
    if not isinstance(d, dict):
        return []
    v = d.get(key)
    return v if isinstance(v, list) else []


def _normalize_path(path: str, target_path: Optional[str]) -> str:
    """Return the path normalised relative to target_path when possible.

    - Strips a leading ``./`` (claude often emits these).
    - Converts an absolute path under ``target_path`` to its relative form.
    - Leaves anything else untouched (no aggressive symlink resolution).
    """
    if not path:
        return path
    p = path.strip()
    if p.startswith("./"):
        p = p[2:]
    if target_path and p.startswith("/"):
        try:
            rel = Path(p).resolve().relative_to(Path(target_path).resolve())
            return str(rel)
        except (ValueError, OSError):
            pass  # not under target_path; leave as-is
    return p


def _normalize_paths(context_map: Dict[str, Any],
                     target_path: Optional[str]) -> None:
    for section in _LOCATION_BEARING_SECTIONS:
        for entry in _list_at(context_map, section):
            if not isinstance(entry, dict):
                continue
            file = entry.get("file")
            # Only operate on strings — guard against LLM emitting a list,
            # int, or other non-string for `file:`. _normalize_path's
            # str.strip() would otherwise raise.
            if isinstance(file, str) and file:
                entry["file"] = _normalize_path(file, target_path)


def _find_containing_function(file_info: Dict[str, Any],
                               line: int) -> Optional[Dict[str, Any]]:
    """Return the function in file_info whose line range contains ``line``.

    Strict pass: collect every function with both ``line_start`` and
    ``line_end`` such that ``line_start ≤ line ≤ line_end`` and return
    the one with the smallest span (so nested functions get attributed
    to the innermost match, not the enclosing function).

    Fallback (when no strict match): return the function with the
    closest preceding ``line_start`` — best-effort for inventories that
    don't track function ends. Under-approximates: a line past the end
    of the closest preceding function still gets attributed to it.
    """
    funcs = file_info.get("items")
    if not isinstance(funcs, list):
        funcs = _list_at(file_info, "functions")
    # Strict pass: collect every function whose range contains the line,
    # then pick the smallest span. Smallest-span wins so that nested
    # functions (Python closures, JS inner functions) get attributed to
    # the innermost match, not the outer enclosing function.
    strict_matches = []
    for fn in funcs:
        if not isinstance(fn, dict):
            continue
        line_start = fn.get("line_start") or fn.get("line")
        line_end = fn.get("line_end")
        # Require both bounds to be ints — string-typed line numbers
        # from a corrupt checklist would otherwise raise TypeError on
        # the int-vs-str comparison below. Also reject bools to avoid
        # weird behaviour even though bool is a subclass of int.
        if not isinstance(line_start, int) or isinstance(line_start, bool):
            continue
        if not isinstance(line_end, int) or isinstance(line_end, bool):
            continue
        if line_start <= line <= line_end:
            strict_matches.append((line_end - line_start, fn))
    if strict_matches:
        strict_matches.sort(key=lambda c: c[0])
        return strict_matches[0][1]
    # Fallback: closest preceding line_start (under-approximates but better
    # than nothing for inventories without line_end).
    candidates = []
    for fn in funcs:
        if not isinstance(fn, dict):
            continue
        line_start = fn.get("line_start") or fn.get("line")
        if not isinstance(line_start, int) or isinstance(line_start, bool):
            continue
        if line_start > line:
            continue
        candidates.append((line_start, fn))
    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0], reverse=True)
    return candidates[0][1]


def _backfill_and_validate_locations(context_map: Dict[str, Any],
                                      files_by_path: Dict[str, Dict[str, Any]]
                                      ) -> None:
    for section in _LOCATION_BEARING_SECTIONS:
        for entry in _list_at(context_map, section):
            if not isinstance(entry, dict):
                continue
            file = entry.get("file")
            line = entry.get("line")
            # files_by_path lookup uses dict.get(), which raises
            # TypeError on unhashable types (list/dict). Require string.
            if not isinstance(file, str) or not file or not isinstance(line, int):
                continue

            file_info = files_by_path.get(file)
            if file_info is None:
                logger.warning(
                    "normalize_context_map: %s entry references file %s "
                    "not present in checklist (likely LLM hallucination)",
                    section, escape_nonprintable(file),
                )
                continue

            total_lines = file_info.get("lines")
            if isinstance(total_lines, int) and line > total_lines:
                # escape_nonprintable on `file` so any control / ANSI / BIDI
                # chars in an attacker-influenced filename get rendered as
                # \xHH literals; raw %s would let them corrupt the terminal.
                logger.warning(
                    "normalize_context_map: %s entry references %s:%d "
                    "but file has only %d lines (likely LLM hallucination)",
                    section, escape_nonprintable(file), line, total_lines,
                )
                continue

            # Backfill name if absent. Only backfill string names — a
            # corrupt checklist with a non-string `name` field would
            # otherwise propagate the type bug into context_map and
            # crash enrich_checklist's tuple-key lookup downstream.
            if not entry.get("name"):
                func = _find_containing_function(file_info, line)
                if func:
                    func_name = func.get("name")
                    if isinstance(func_name, str) and func_name:
                        entry["name"] = func_name


def _validate_cross_refs(context_map: Dict[str, Any]) -> None:
    # Set construction requires hashable values — if claude emits an id as
    # a list / dict, the comprehension would raise. Constrain to strings.
    ep_ids = {
        e.get("id") for e in _list_at(context_map, "entry_points")
        if isinstance(e, dict) and isinstance(e.get("id"), str) and e.get("id")
    }
    sink_ids = {
        s.get("id") for s in _list_at(context_map, "sink_details")
        if isinstance(s, dict) and isinstance(s.get("id"), str) and s.get("id")
    }
    for flow in _list_at(context_map, "unchecked_flows"):
        if not isinstance(flow, dict):
            continue
        # entry_point / sink may legitimately be either a single ID string
        # ("EP-001") or a list of IDs (multiple sources reaching one sink).
        # Collect into a uniform list before the membership check — set
        # membership on a raw list would raise TypeError (lists unhashable).
        for ep_ref in _as_id_list(flow.get("entry_point")):
            if ep_ref not in ep_ids:
                logger.warning(
                    "normalize_context_map: unchecked_flow references "
                    "entry_point %s not in entry_points list",
                    escape_nonprintable(ep_ref),
                )
        for sink_ref in _as_id_list(flow.get("sink")):
            if sink_ref not in sink_ids:
                logger.warning(
                    "normalize_context_map: unchecked_flow references "
                    "sink %s not in sink_details list",
                    escape_nonprintable(sink_ref),
                )


def _as_id_list(value: Any) -> List[str]:
    """Coerce a context-map ID reference into a list of string IDs.

    Accepts a single string, a list of strings (or mixed), or any other
    type. Non-string elements are dropped silently rather than raising —
    cross-ref validation is best-effort.
    """
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for v in value if isinstance(v, str) and v]
    return []


def enrich_checklist(checklist: Dict[str, Any], context_map: Dict[str, Any],
                     output_dir: str = None) -> Dict[str, Any]:
    """Mark entry points and sinks as high-priority in a checklist.

    Mutates checklist in place. Returns the checklist for chaining.
    If output_dir is provided, saves the enriched checklist (symlink-safe).

    Pipeline (in order):
      1. Normalise the context-map (path conventions, name backfill, etc.).
      2. Clear any prior bridge-written priority markers from the
         checklist — re-runs reflect the current context-map exactly,
         not stale accumulation from previous runs.
      3. Build a (file, name|None) → reasons lookup from entry_points
         and sink_details.
      4. Walk the checklist; mark functions matching either file-level
         or function-level lookups; reasons accumulate as ``"+"``-joined
         sorted strings (single ``"sink"``, paired ``"entry_point+sink"``).
      5. Write ``priority_targets`` from ``unchecked_flows`` (cleared in
         step 2 so absent unchecked_flows means absent priority_targets).

    **Side effect:** also mutates ``context_map`` in place via
    ``normalize_context_map`` so missing names get backfilled (enabling
    function-level matching) and paths get normalised (avoiding silent
    strict-equality misses). Callers that need an unmodified context_map
    should pass a deep copy.
    """
    # Both inputs must be dict-shaped — defensive against malformed
    # callers (e.g. a list-typed checklist would crash on .get()).
    if not isinstance(checklist, dict) or not isinstance(context_map, dict):
        return checklist
    if not checklist or not context_map:
        return checklist

    # Normalise the context-map first so the lookup keys are consistent
    # with the checklist's path conventions and function names get filled
    # in from line ranges where claude omitted them.
    normalize_context_map(context_map, checklist,
                          target_path=checklist.get("target_path"))

    # Clear bridge-written priority markers from any prior enrich run.
    # Without this, a function previously marked priority=high would
    # retain that marker even after a refreshed context-map no longer
    # references it (stale data leak across re-runs). Re-running should
    # always reflect the current context-map's reasons exactly.
    # enrich_checklist is the sole writer of these fields, so the clear
    # is safe — verified by grep across the codebase.
    _clear_prior_priority_markers(checklist)

    # Build lookup: (relative_path, function_name_or_None) → set of reasons.
    # When the context map provides a function name on an entry_point /
    # sink_detail entry we use it to scope the marker to that function only;
    # when name is absent we fall back to file-level marking (every function
    # in the file). Reasons accumulate so a function that is both an entry
    # point and a sink gets both labels rather than only the one written
    # last.
    priority_functions: Dict[tuple, set] = {}

    def _record(entry: Any, reason: str) -> None:
        """Record a priority reason against the (file, name) key.

        Constrains both file and name to strings — tuple keys go into a
        dict and a list/dict-typed file or name would be unhashable and
        crash setdefault. Drops malformed entries silently rather than
        propagating the type bug. None for absent name (file-level
        marking).
        """
        if not isinstance(entry, dict):
            return
        file_path = entry.get("file", "")
        if not isinstance(file_path, str) or not file_path:
            return
        raw_name = entry.get("name")
        name = raw_name if isinstance(raw_name, str) and raw_name else None
        priority_functions.setdefault((file_path, name), set()).add(reason)

    for ep in _list_at(context_map, "entry_points"):
        _record(ep, "entry_point")
    for sink in _list_at(context_map, "sink_details"):
        _record(sink, "sink")

    # Walk checklist and mark matching functions. A function inherits
    # file-level reasons (entries written without a name) plus any
    # reasons keyed to its specific function name.
    for file_info in checklist.get("files", []):
        if not isinstance(file_info, dict):
            continue
        path = file_info.get("path", "")
        if not isinstance(path, str):
            continue
        file_level_reasons = priority_functions.get((path, None), set())

        funcs = file_info.get("items")
        if not isinstance(funcs, list):
            funcs = _list_at(file_info, "functions")
        for func in funcs:
            if not isinstance(func, dict):
                continue
            raw_fname = func.get("name")
            # Function-level lookup needs a string name — non-string
            # would crash dict.get on the tuple key. Falling back to ""
            # means we just won't find a function-level match (file-level
            # reasons may still apply).
            fname = raw_fname if isinstance(raw_fname, str) else ""
            func_level_reasons = priority_functions.get((path, fname), set())
            reasons = file_level_reasons | func_level_reasons
            if reasons:
                func["priority"] = "high"
                # Deterministic concat — single reason renders as before
                # ("entry_point" or "sink"); the entry+sink case becomes
                # "entry_point+sink" (sorted alphabetically). Existing
                # consumers (analysis prompt builder, agent metadata copy)
                # render the string verbatim, no equality checks, so the
                # combined form passes through cleanly.
                func["priority_reason"] = "+".join(sorted(reasons))

    # Add unchecked flows as priority targets at the checklist level.
    # Each target also carries resolved entry-point / sink details
    # (file, line, name) looked up from the context-map, so downstream
    # consumers (Stage B prompts, /diagram, etc.) don't have to do the
    # ID → details join themselves. Additive — original ID fields are
    # preserved.
    unchecked = context_map.get("unchecked_flows")
    # Require a real list — accepting any truthy value would silently
    # produce an empty priority_targets for malformed shapes (e.g.
    # context-map with unchecked_flows: "string"), which is more
    # surprising than just leaving the cleared key absent.
    if isinstance(unchecked, list) and unchecked:
        ep_by_id, sink_by_id = _index_entries_by_id(context_map)
        targets = [
            _build_priority_target(flow, ep_by_id, sink_by_id)
            for flow in unchecked
            if isinstance(flow, dict)
        ]
        if targets:
            checklist["priority_targets"] = targets
            logger.info(
                "understand_bridge: marked %d unchecked flows as priority targets",
                len(targets),
            )

    if output_dir:
        from core.inventory import save_checklist
        save_checklist(output_dir, checklist)

    return checklist


def _index_entries_by_id(context_map: Dict[str, Any]
                          ) -> Tuple[Dict[str, Dict[str, Any]],
                                     Dict[str, Dict[str, Any]]]:
    """Build {id → entry} lookups for entry_points and sink_details.

    Skips entries with missing or non-string IDs (matching the defensive
    posture of _validate_cross_refs). Returns a pair (ep_by_id, sink_by_id).
    """
    ep_by_id: Dict[str, Dict[str, Any]] = {}
    for ep in _list_at(context_map, "entry_points"):
        if not isinstance(ep, dict):
            continue
        ep_id = ep.get("id")
        if isinstance(ep_id, str) and ep_id:
            ep_by_id[ep_id] = ep
    sink_by_id: Dict[str, Dict[str, Any]] = {}
    for sd in _list_at(context_map, "sink_details"):
        if not isinstance(sd, dict):
            continue
        sd_id = sd.get("id")
        if isinstance(sd_id, str) and sd_id:
            sink_by_id[sd_id] = sd
    return ep_by_id, sink_by_id


def _resolve_id_to_details(value: Any, by_id: Dict[str, Dict[str, Any]]
                            ) -> List[Dict[str, Any]]:
    """Resolve a single ID or list of IDs into a list of detail dicts.

    Each detail keeps only the fields a downstream consumer actually
    needs: id, file, line, name. Missing IDs (typos, etc.) are dropped
    silently — _validate_cross_refs has already warned about them.
    Always returns a list for shape consistency.

    Type-checks each copied field — drops malformed values (list-typed
    file, string-typed line, etc.) rather than propagating the type bug
    to downstream consumers.
    """
    resolved: List[Dict[str, Any]] = []
    for ref in _as_id_list(value):
        entry = by_id.get(ref)
        if not entry:
            continue
        out: Dict[str, Any] = {"id": ref}
        # file / name must be non-empty strings; line must be int (and
        # not bool, which is an int subclass in Python).
        file_v = entry.get("file")
        if isinstance(file_v, str) and file_v:
            out["file"] = file_v
        line_v = entry.get("line")
        if isinstance(line_v, int) and not isinstance(line_v, bool):
            out["line"] = line_v
        name_v = entry.get("name")
        if isinstance(name_v, str) and name_v:
            out["name"] = name_v
        resolved.append(out)
    return resolved


def _build_priority_target(flow: Dict[str, Any],
                            ep_by_id: Dict[str, Dict[str, Any]],
                            sink_by_id: Dict[str, Dict[str, Any]]
                            ) -> Dict[str, Any]:
    """Build a priority_targets entry from one unchecked_flow.

    Preserves the original raw ID fields for backward compatibility and
    adds ``entry_points_resolved`` / ``sinks_resolved`` lists with each
    referenced entry's file / line / name pulled from the context-map.
    """
    return {
        "entry_point": flow.get("entry_point"),
        "sink": flow.get("sink"),
        "missing_boundary": flow.get("missing_boundary"),
        "source": "understand:map",
        "entry_points_resolved": _resolve_id_to_details(
            flow.get("entry_point"), ep_by_id),
        "sinks_resolved": _resolve_id_to_details(
            flow.get("sink"), sink_by_id),
    }


def _clear_prior_priority_markers(checklist: Dict[str, Any]) -> None:
    """Remove bridge-written priority data so re-enrichment starts clean.

    Targets:
      - per-function ``priority`` and ``priority_reason`` fields
      - top-level ``priority_targets`` list

    Without this, a refreshed context-map that no longer references a
    previously-marked function would leave the stale marker in place,
    misleading downstream consumers (analysis prompt enrichment etc.)
    into thinking a now-irrelevant function is on a security-sensitive
    path.
    """
    checklist.pop("priority_targets", None)
    for file_info in _list_at(checklist, "files"):
        if not isinstance(file_info, dict):
            continue
        funcs = file_info.get("items")
        if not isinstance(funcs, list):
            funcs = _list_at(file_info, "functions")
        for func in funcs:
            if not isinstance(func, dict):
                continue
            func.pop("priority", None)
            func.pop("priority_reason", None)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _references_file(entry: Dict[str, Any], stale_files: Set[str]) -> bool:
    """Check if a context-map entry references any stale file.

    Entries use different formats:
    - entry_points/sink_details: {"file": "foo.c", ...}
    - sources: {"entry": "argv[1] @ foo.c:6"}
    - sinks: {"location": "foo.c:6 — strcpy(...)"}
    - trust_boundaries: {"boundary": "...", "check": "..."}
    """
    import re

    # Direct file field (entry_points, sink_details, trust_boundaries).
    # Constrain to strings — list/dict values would crash set membership
    # (lists aren't hashable). Pre-existing weakness exposed once the
    # upstream normalize started letting non-string `file:` values
    # through unmodified.
    f = entry.get("file", "")
    if isinstance(f, str) and f and f in stale_files:
        return True

    # Embedded in string fields — extract filename before ":"
    # Patterns: "... @ file.c:N", "file.c:N — ...", "src/auth.py:12"
    for field in ("entry", "location", "check"):
        val = entry.get(field, "")
        if not isinstance(val, str) or not val:
            continue
        # Extract all "word.ext:digits" tokens (filenames with line numbers)
        for match in re.findall(r'[\w./+-]+\.\w+(?=:\d)', val):
            if match in stale_files:
                return True

    return False


def _filter_context_map(context_map: Dict[str, Any], stale_files: Set[str]) -> int:
    """Remove entries referencing stale files from the context map. Mutates in place.

    Returns the number of entries removed.
    """
    if not stale_files:
        return 0

    removed = 0

    # Filter list-of-dict fields
    for key in ("entry_points", "sources", "sinks", "sink_details",
                "trust_boundaries", "boundary_details"):
        items = context_map.get(key)
        if not isinstance(items, list):
            continue
        clean = [e for e in items if not _references_file(e, stale_files)]
        removed += len(items) - len(clean)
        context_map[key] = clean

    # Filter unchecked_flows — references entry_points/sinks by ID, so
    # resolve IDs to files first, then drop flows touching stale files.
    stale_ep_ids: Set[str] = set()
    stale_sink_ids: Set[str] = set()

    # We need the original entry_points/sink_details to know which IDs
    # were removed. But we already filtered those lists above. Instead,
    # collect IDs from the entries we kept and drop flows referencing
    # any ID that's NOT in the kept set.
    kept_ep_ids = {ep.get("id") for ep in context_map.get("entry_points", []) if ep.get("id")}
    kept_sink_ids = {s.get("id") for s in context_map.get("sink_details", []) if s.get("id")}

    flows = context_map.get("unchecked_flows", [])
    if isinstance(flows, list):
        clean = [
            f for f in flows
            if f.get("entry_point") in kept_ep_ids
            and f.get("sink") in kept_sink_ids
        ]
        removed += len(flows) - len(clean)
        context_map["unchecked_flows"] = clean

    return removed


def _load_context_map(understand_dir: Path) -> Optional[Dict[str, Any]]:
    #Load context-map.json from an understand output directory.
    context_map_path = understand_dir / "context-map.json"
    if not context_map_path.exists():
        return None

    data = load_json(context_map_path)
    if not isinstance(data, dict):
        logger.warning("understand_bridge: context-map.json is not a JSON object")
        return None

    # Basic shape validation — sources and sinks should be lists
    for key in ("sources", "sinks", "trust_boundaries"):
        val = data.get(key)
        if val is not None and not isinstance(val, list):
            logger.warning("understand_bridge: context-map.json '%s' is not a list, skipping", key)
            data[key] = []

    return data


def _merge_attack_surface(
    context_map: Dict[str, Any],
    validate_dir: Path,
    understand_dir: Path,
) -> Dict[str, Any]:
    # Populate or merge attack-surface.json from context-map data.
    surface_path = validate_dir / "attack-surface.json"

    # Extract the three required keys from the context map
    new_sources = context_map.get("sources", [])
    new_sinks = context_map.get("sinks", [])
    new_boundaries = context_map.get("trust_boundaries", [])

    # Annotate trust boundaries with gap information from boundary_details
    gap_count = 0
    all_boundary_details = context_map.get("boundary_details", [])
    for boundary in new_boundaries:
        for bd in all_boundary_details:
            if bd.get("gaps") and _boundary_matches(boundary, bd):
                boundary["gaps"] = bd["gaps"]
                boundary["gaps_source"] = "understand:map"
                gap_count += 1
                break

    changed = False
    if surface_path.exists():
        existing = load_json(surface_path) or {}
        merged_sources = _merge_list_by_key(
            existing.get("sources", []), new_sources, key="entry"
        )
        merged_sinks = _merge_list_by_key(
            existing.get("sinks", []), new_sinks, key="location"
        )
        merged_boundaries = _merge_list_by_key(
            existing.get("trust_boundaries", []), new_boundaries, key="boundary"
        )
        # Only rewrite if the merge added something
        changed = (len(merged_sources) != len(existing.get("sources", []))
                   or len(merged_sinks) != len(existing.get("sinks", []))
                   or len(merged_boundaries) != len(existing.get("trust_boundaries", [])))
    else:
        merged_sources = new_sources
        merged_sinks = new_sinks
        merged_boundaries = new_boundaries
        changed = bool(new_sources or new_sinks or new_boundaries)

    if changed:
        attack_surface = {
            "sources": merged_sources,
            "sinks": merged_sinks,
            "trust_boundaries": merged_boundaries,
            "_imported_from": str(understand_dir / "context-map.json"),
            "_imported_at": datetime.now(timezone.utc).isoformat(),
        }
        save_json(surface_path, attack_surface)

    unchecked_count = len(context_map.get("unchecked_flows", []))
    return {
        "sources": len(merged_sources),
        "sinks": len(merged_sinks),
        "trust_boundaries": len(merged_boundaries),
        "gaps": gap_count,
        "unchecked_flows": unchecked_count,
    }


def _trace_references_stale(trace: Dict[str, Any], stale_files: Set[str]) -> bool:
    """Check if a flow trace references any stale file via its steps."""
    import re

    for step in trace.get("steps", []):
        # Direct file field — exact match
        f = step.get("file", "")
        if f and f in stale_files:
            return True
        # Embedded in action/result strings — extract filenames via regex
        for field in ("action", "result"):
            val = step.get(field, "")
            if val:
                for match in re.findall(r'[\w./+-]+\.\w+(?=:\d)', val):
                    if match in stale_files:
                        return True
    return False


def _import_flow_traces(
    understand_dir: Path,
    validate_dir: Path,
    stale_files: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    # Import flow-trace-*.json files as initial entries in attack-paths.json.
    trace_files = sorted(understand_dir.glob("flow-trace-*.json"))
    if not trace_files:
        return {"count": 0, "imported_as_paths": 0, "skipped_stale": 0}

    if stale_files is None:
        stale_files = set()

    paths_path = validate_dir / "attack-paths.json"
    existing_paths: List[Dict[str, Any]] = []
    if paths_path.exists():
        loaded = load_json(paths_path)
        if isinstance(loaded, list):
            existing_paths = loaded

    # Track which IDs are already present to avoid duplicates
    existing_ids = {p.get("id") for p in existing_paths if p.get("id")}

    imported = 0
    skipped_stale = 0
    for trace_file in trace_files:
        trace = load_json(trace_file)
        if not isinstance(trace, dict):
            logger.warning("understand_bridge: skipping malformed trace file %s",
                           escape_nonprintable(str(trace_file)))
            continue

        path_id = trace.get("id", trace_file.stem)
        if path_id in existing_ids:
            logger.debug("understand_bridge: skipping already-imported trace %s",
                         escape_nonprintable(str(path_id)))
            continue

        if stale_files and _trace_references_stale(trace, stale_files):
            logger.info("understand_bridge: skipping stale trace %s",
                        escape_nonprintable(str(path_id)))
            skipped_stale += 1
            continue

        attack_path = _trace_to_attack_path(trace, trace_file)
        existing_paths.append(attack_path)
        existing_ids.add(path_id)
        imported += 1

    if imported > 0:
        save_json(paths_path, existing_paths)

    return {"count": len(trace_files), "imported_as_paths": imported, "skipped_stale": skipped_stale}


def _trace_to_attack_path(trace: Dict[str, Any], trace_file: Path) -> Dict[str, Any]:
    #Convert a flow-trace dict into an attack-paths entry.

    path = {
        "id": trace.get("id", trace_file.stem),
        "name": trace.get("name", f"Imported trace: {trace_file.stem}"),
        # finding may not exist yet (trace ran before /validate) — leave blank
        "finding": trace.get("finding", ""),
        "steps": trace.get("steps", []),
        "proximity": trace.get("proximity", 0),
        "blockers": trace.get("blockers", []),
        "branches": trace.get("branches", []),
        "status": "uncertain",
        "source": TRACE_SOURCE_LABEL,
        "imported_from": str(trace_file),
        "imported_at": datetime.now(timezone.utc).isoformat(),
    }

    # Carry through attacker control summary as an annotation — useful context
    # for Stage B when forming hypotheses without duplicating the trace schema.
    attacker_control = trace.get("attacker_control")
    if attacker_control:
        path["attacker_control"] = attacker_control

    # If the trace summary has a verdict, record it as a note for Stage B
    summary = trace.get("summary", {})
    if summary.get("verdict"):
        path["trace_verdict"] = summary["verdict"]

    # Forward SMT path-feasibility hints when present and well-formed.  Both
    # fields are optional — Stage E falls back to extracting conditions from
    # source if absent.  Malformed values are dropped with a logged warning
    # rather than passed through; better Stage E re-extracts than confuses
    # itself with bad data.
    pc = _validate_path_conditions(trace.get("path_conditions"), str(trace_file))
    if pc is not None:
        path["path_conditions"] = pc
    pp = _validate_path_profile(trace.get("path_profile"), str(trace_file))
    if pp is not None:
        path["path_profile"] = pp

    return path


def _validate_path_conditions(
    conditions: Any, source: str,
) -> Optional[List[Any]]:
    """Validate the optional ``path_conditions`` field on a flow trace.

    Returns the conditions list if every element is a string or a
    ``{"text": str, ...}`` dict (matching the shape
    ``raptor-smt-validate-path --stdin`` accepts).  Returns ``None`` —
    dropping the field entirely with a logged warning — if the value is
    malformed.  Better the consumer re-extracts than confuses itself
    with bad data.
    """
    if conditions is None:
        return None
    if not isinstance(conditions, list):
        logger.warning(
            "understand_bridge: %s path_conditions must be a list, got %s — dropping",
            source, type(conditions).__name__,
        )
        return None
    for i, c in enumerate(conditions):
        if isinstance(c, str):
            continue
        if isinstance(c, dict):
            text = c.get("text") or c.get("condition")
            if not isinstance(text, str) or not text:
                logger.warning(
                    "understand_bridge: %s path_conditions[%d] missing/invalid 'text' — dropping field",
                    source, i,
                )
                return None
            continue
        logger.warning(
            "understand_bridge: %s path_conditions[%d] must be str or dict, got %s — dropping field",
            source, i, type(c).__name__,
        )
        return None
    return conditions


def _validate_path_profile(profile: Any, source: str) -> Optional[str]:
    """Validate the optional ``path_profile`` field on a flow trace.

    Must be one of the stdint-style names accepted by
    ``raptor-smt-validate-path``.  Drops the field with a warning on
    anything else.
    """
    if profile is None:
        return None
    if not isinstance(profile, str) or profile not in _VALID_PROFILE_NAMES:
        logger.warning(
            "understand_bridge: %s path_profile must be one of %s, got %r — dropping",
            source, sorted(_VALID_PROFILE_NAMES), profile,
        )
        return None
    return profile


def _merge_list_by_key(
    existing: List[Dict], incoming: List[Dict], key: str
) -> List[Dict]:
    #Merge two lists of dicts, de-duplicating on a string key field.

    existing_keys = {
        item.get(key, "")
        for item in existing
        if item.get(key)
    }

    result = list(existing)
    for item in incoming:
        item_key = item.get(key, "")
        if item_key and item_key in existing_keys:
            continue
        result.append(item)
        if item_key:
            existing_keys.add(item_key)

    return result


def _boundary_matches(boundary: Dict[str, Any], detail: Dict[str, Any]) -> bool:
    """Check whether a trust_boundaries entry corresponds to a boundary_details entry.

    Uses normalised substring matching with a minimum length to avoid
    short strings like "a" matching everything.
    """
    boundary_name = boundary.get("boundary", "").lower().strip()
    detail_id = detail.get("id", "").lower().strip()

    if not boundary_name or not detail_id:
        return False

    # Require the shorter string to be at least 4 chars to avoid
    # false positives from very short boundary names
    shorter = min(len(boundary_name), len(detail_id))
    if shorter < 4:
        return boundary_name == detail_id

    return boundary_name in detail_id or detail_id in boundary_name
