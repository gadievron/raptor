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

    from core.understand_bridge import load_understand_context, enrich_checklist

    # Auto-detect from active project, or pass an explicit path
    bridge = load_understand_context(understand_dir=Path("/some/understand-run"), validate_dir=output_dir)
    if bridge["context_map"]:
        enrich_checklist(checklist, bridge["context_map"])

Auto-detection (project mode):

    from core.understand_bridge import find_understand_dir
    understand_dir = find_understand_dir(project_output_dir)  # None if not found
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.json import load_json, save_json

logger = logging.getLogger(__name__)

# Label used in attack-paths to mark entries imported from /understand traces.
# Stage B uses this to distinguish its own paths from pre-loaded ones.
TRACE_SOURCE_LABEL = "understand:trace"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_understand_dir(project_output_dir: Path) -> Optional[Path]:
    """Find the most recent /understand run inside a project output directory.

    Uses infer_command_type from core.run to identify understand runs regardless
    of directory naming convention. Returns the most recent by modification time,
    or None if none exists.
    """
    from core.run import infer_command_type

    project_output_dir = Path(project_output_dir)
    if not project_output_dir.is_dir():
        return None

    candidates = [
        d for d in sorted(project_output_dir.iterdir(),
                          key=lambda d: d.stat().st_mtime, reverse=True)
        if d.is_dir()
        and not d.name.startswith((".", "_"))
        and infer_command_type(d) == "understand"
        and (d / "context-map.json").exists()
    ]

    if candidates:
        logger.debug("Auto-detected understand dir: %s", candidates[0])
        return candidates[0]

    return None


def load_understand_context(
    understand_dir: Path,
    validate_dir: Path,
) -> Dict[str, Any]:
    #Import /understand outputs as /validate starting state.
    understand_dir = Path(understand_dir)
    validate_dir = Path(validate_dir)
    validate_dir.mkdir(parents=True, exist_ok=True)

    summary: Dict[str, Any] = {
        "understand_dir": str(understand_dir),
        "context_map_loaded": False,
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

    summary["context_map_loaded"] = True
    summary["context_map"] = context_map

    # --- Populate attack-surface.json ---
    surface_stats = _merge_attack_surface(context_map, validate_dir, understand_dir)
    summary["attack_surface"] = surface_stats

    # --- Import flow-trace-*.json into attack-paths.json ---
    trace_stats = _import_flow_traces(understand_dir, validate_dir)
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


def enrich_checklist(checklist: Dict[str, Any], context_map: Dict[str, Any]) -> Dict[str, Any]:
    """Mark entry points and sinks as high-priority in a checklist.

    Mutates checklist in place. Returns the checklist for chaining.
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

    return checklist


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

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


def _import_flow_traces(
    understand_dir: Path,
    validate_dir: Path,
) -> Dict[str, Any]:
    # Import flow-trace-*.json files as initial entries in attack-paths.json.
    trace_files = sorted(understand_dir.glob("flow-trace-*.json"))
    if not trace_files:
        return {"count": 0, "imported_as_paths": 0}

    paths_path = validate_dir / "attack-paths.json"
    existing_paths: List[Dict[str, Any]] = []
    if paths_path.exists():
        loaded = load_json(paths_path)
        if isinstance(loaded, list):
            existing_paths = loaded

    # Track which IDs are already present to avoid duplicates
    existing_ids = {p.get("id") for p in existing_paths if p.get("id")}

    imported = 0
    for trace_file in trace_files:
        trace = load_json(trace_file)
        if not isinstance(trace, dict):
            logger.warning("understand_bridge: skipping malformed trace file %s", trace_file)
            continue

        path_id = trace.get("id", trace_file.stem)
        if path_id in existing_ids:
            logger.debug("understand_bridge: skipping already-imported trace %s", path_id)
            continue

        attack_path = _trace_to_attack_path(trace, trace_file)
        existing_paths.append(attack_path)
        existing_ids.add(path_id)
        imported += 1

    if imported > 0:
        save_json(paths_path, existing_paths)

    return {"count": len(trace_files), "imported_as_paths": imported}


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
