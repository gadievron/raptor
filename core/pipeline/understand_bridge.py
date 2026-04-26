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

    from core.pipeline.understand_bridge import find_understand_output, load_understand_context, enrich_checklist

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
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.json import load_json, save_json

logger = logging.getLogger(__name__)

# Label used in attack-paths to mark entries imported from /understand traces.
# Stage B uses this to distinguish its own paths from pre-loaded ones.
TRACE_SOURCE_LABEL = "understand:trace"


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
            ", ".join(sorted(best_stale_files)),
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
    import hashlib

    target = Path(target_path)
    stale: Set[str] = set()
    for rel_path, u_hash in understand_hashes.items():
        full_path = target / rel_path
        if not full_path.is_file():
            # File deleted since understand ran
            stale.add(rel_path)
            continue
        disk_hash = hashlib.sha256(full_path.read_bytes()).hexdigest()
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

    # --- Filter entries referencing stale files ---
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


def enrich_checklist(checklist: Dict[str, Any], context_map: Dict[str, Any],
                     output_dir: str = None) -> Dict[str, Any]:
    """Mark entry points and sinks as high-priority in a checklist.

    Mutates checklist in place. Returns the checklist for chaining.
    If output_dir is provided, saves the enriched checklist (symlink-safe).
    """
    if not checklist or not context_map:
        return checklist

    # Build lookup sets: (relative_path, function_name) → reason
    priority_functions: Dict[tuple, str] = {}

    for ep in context_map.get("entry_points", []):
        file_path = ep.get("file", "")
        if file_path:
            # Entry points reference a file but not always a specific function —
            # mark the file itself so Stage B reads the whole entry handler.
            priority_functions[(file_path, None)] = "entry_point"

    for sink in context_map.get("sink_details", []):
        file_path = sink.get("file", "")
        if file_path:
            priority_functions[(file_path, None)] = "sink"

    # Walk checklist and mark matching functions
    for file_info in checklist.get("files", []):
        path = file_info.get("path", "")
        file_reason = priority_functions.get((path, None))

        if file_reason:
            # Mark all functions in this file as high priority
            for func in file_info.get("items", file_info.get("functions", [])):
                func["priority"] = "high"
                func["priority_reason"] = file_reason

    # Add unchecked flows as priority targets at the checklist level
    unchecked = context_map.get("unchecked_flows", [])
    if unchecked:
        checklist["priority_targets"] = [
            {
                "entry_point": flow.get("entry_point"),
                "sink": flow.get("sink"),
                "missing_boundary": flow.get("missing_boundary"),
                "source": "understand:map",
            }
            for flow in unchecked
        ]
        logger.info(
            "understand_bridge: marked %d unchecked flows as priority targets",
            len(unchecked),
        )

    if output_dir:
        from core.inventory import save_checklist
        save_checklist(output_dir, checklist)

    return checklist


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

    # Direct file field (entry_points, sink_details, trust_boundaries)
    f = entry.get("file", "")
    if f and f in stale_files:
        return True

    # Embedded in string fields — extract filename before ":"
    # Patterns: "... @ file.c:N", "file.c:N — ...", "src/auth.py:12"
    for field in ("entry", "location", "check"):
        val = entry.get(field, "")
        if not val:
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
            "_imported_at": datetime.now().isoformat(),
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
            logger.warning("understand_bridge: skipping malformed trace file %s", trace_file)
            continue

        path_id = trace.get("id", trace_file.stem)
        if path_id in existing_ids:
            logger.debug("understand_bridge: skipping already-imported trace %s", path_id)
            continue

        if stale_files and _trace_references_stale(trace, stale_files):
            logger.info("understand_bridge: skipping stale trace %s", path_id)
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
        "imported_at": datetime.now().isoformat(),
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

    return path


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
