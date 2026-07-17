"""Enrich context-map.json with mechanically-discovered sinks.

Uses :mod:`core.inventory.sink_discovery` to compute:

1. **Reverse sink reachability** — which entry points and internal
   functions can transitively reach a dangerous sink through the call
   graph. Each sink_detail gains a ``reverse_reachable_from`` field
   listing the functions that can reach it, and each entry_point gains
   a ``reachable_sinks`` field listing the dangerous targets reachable
   from it.

2. **Mechanically-discovered sinks** — dangerous call sites that the
   LLM's MAP-3 may have missed. Merged into ``sink_details`` with
   ``source: "mechanical"`` to distinguish from LLM-emitted entries.

3. **Framework APIs** — autonomously discovered high-frequency call
   targets that span many files. Added to ``meta.frameworks`` in the
   context map, complementing or seeding the LLM's MAP-4 output.

Runs as MAP-5f after the normaliser and forward-reachable enrichment.
Idempotent — safe to re-run.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Set

from core.inventory.sink_discovery import (
    SinkDiscoveryResult,
    discover_sinks_for_target,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 10
DEFAULT_FRAMEWORK_THRESHOLD = 5
DEFAULT_FRAMEWORK_MIN_FILES = 3
MAX_FRAMEWORK_APIS = 30


def enrich_with_sink_discovery(
    context_map: Dict[str, Any],
    target_path: Path,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    framework_threshold: int = DEFAULT_FRAMEWORK_THRESHOLD,
    framework_min_files: int = DEFAULT_FRAMEWORK_MIN_FILES,
) -> int:
    """Enrich a context-map dict in place with sink discovery results.

    Returns the number of entries enriched (sinks + entry points).
    """
    result = discover_sinks_for_target(
        target_path,
        max_depth=max_depth,
        framework_threshold=framework_threshold,
        framework_min_files=framework_min_files,
    )

    modified = 0

    # 1. Merge mechanically-discovered sinks into sink_details
    modified += _merge_discovered_sinks(context_map, result)

    # 2. Annotate entry points with reachable sinks
    modified += _annotate_entry_points(context_map, result)

    # 3. Add framework APIs to meta
    modified += _merge_framework_apis(context_map, result)

    # 4. Add the summary to context_map root (always counts as modified
    # so the caller persists the result even if only framework APIs
    # or the summary changed)
    context_map["sink_discovery"] = result.as_dict()
    if result.direct_sinks or result.framework_apis:
        modified = max(modified, 1)

    return modified


def _merge_discovered_sinks(
    context_map: Dict[str, Any],
    result: SinkDiscoveryResult,
) -> int:
    """Merge mechanically-discovered direct sinks into sink_details.

    Only adds sinks not already present (by file+line match).
    """
    sink_details = context_map.get("sink_details")
    if sink_details is None:
        sink_details = []
        context_map["sink_details"] = sink_details

    existing: Set[tuple] = set()
    for sd in sink_details:
        f = sd.get("file", "")
        line = sd.get("line", 0)
        existing.add((f, line))

    added = 0
    next_id = _next_sink_id(sink_details)
    for sink in result.direct_sinks:
        if (sink.file, sink.line) in existing:
            continue
        sink_details.append({
            "id": f"SINK-{next_id:03d}",
            "file": sink.file,
            "line": sink.line,
            "name": sink.function,
            "type": _classify_sink_type(sink.target),
            "dangerous_target": sink.target,
            "source": "mechanical",
            "description": (
                f"Calls {sink.target} — mechanically discovered from "
                f"call graph analysis"
            ),
        })
        next_id += 1
        added += 1

    if added:
        logger.info("sink enrichment: added %d mechanical sinks", added)
    return added


def _annotate_entry_points(
    context_map: Dict[str, Any],
    result: SinkDiscoveryResult,
) -> int:
    """Add reachable_sinks to entry points that can reach dangerous sinks."""
    entry_points = context_map.get("entry_points", [])
    if not entry_points:
        return 0

    # Build lookup: (file, function) → sinks reachable
    reach_map: Dict[tuple, List[str]] = {}
    for sink in result.direct_sinks:
        key = (sink.file, sink.function)
        reach_map.setdefault(key, []).append(sink.target)
    for tr in result.transitive_reach:
        key = (tr.file, tr.function)
        reach_map.setdefault(key, []).extend(tr.sinks)

    enriched = 0
    for ep in entry_points:
        ep_file = ep.get("file", "")
        ep_name = ep.get("name", "")
        key = (ep_file, ep_name)
        sinks = reach_map.get(key)
        if sinks:
            ep["reachable_sinks"] = sorted(set(sinks))
            enriched += 1

    if enriched:
        logger.info(
            "sink enrichment: annotated %d entry points with reachable sinks",
            enriched,
        )
    return enriched


def _merge_framework_apis(
    context_map: Dict[str, Any],
    result: SinkDiscoveryResult,
) -> int:
    """Add discovered framework APIs to meta.frameworks.

    Returns the number of new framework APIs added.
    """
    if not result.framework_apis:
        return 0

    meta = context_map.setdefault("meta", {})

    # Only dedup against LLM-emitted frameworks, not prior mechanical
    # entries (those get replaced wholesale below for idempotency).
    existing_fw = set()
    for fw in meta.get("frameworks", []):
        if isinstance(fw, str):
            existing_fw.add(fw.lower())
        elif isinstance(fw, dict):
            existing_fw.add(fw.get("name", "").lower())

    fresh_mechanical = []
    for api in result.framework_apis[:MAX_FRAMEWORK_APIS]:
        if api.name.lower() not in existing_fw:
            fresh_mechanical.append({
                "name": api.name,
                "caller_count": api.caller_count,
                "source": "mechanical",
            })

    # Replace ALL prior mechanical entries with the fresh set.
    # Keeps non-mechanical entries intact. Idempotent: running
    # twice with the same codebase produces the same list.
    prev = meta.get("frameworks_discovered", [])
    kept = [
        e for e in prev
        if not (isinstance(e, dict) and e.get("source") == "mechanical")
    ]
    if fresh_mechanical:
        kept.extend(fresh_mechanical)
    if kept:
        meta["frameworks_discovered"] = kept
    elif "frameworks_discovered" in meta:
        del meta["frameworks_discovered"]

    added = len(fresh_mechanical)
    if added:
        logger.info(
            "sink enrichment: added %d discovered framework APIs to meta",
            added,
        )
    return added


def _next_sink_id(sink_details: list) -> int:
    """Find the next available SINK-NNN id number."""
    max_id = 0
    for sd in sink_details:
        sid = sd.get("id", "")
        if sid.startswith("SINK-"):
            try:
                max_id = max(max_id, int(sid[5:]))
            except ValueError:
                pass
    return max_id + 1


def _classify_sink_type(target: str) -> str:
    """Map a dangerous target to a sink type category."""
    shell_targets = {
        "os.execute", "os.system", "os.popen", "io.popen",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "popen", "system", "nixio.exec", "nixio.execp",
        "Kernel.system", "Kernel.exec", "exec.Command",
        "os/exec.Command",
        "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW", "WinExec",
    }
    code_exec_targets = {
        "eval", "loadstring", "dofile", "loadfile",
    }
    deser_targets = {
        "pickle.loads", "pickle.load", "yaml.load", "marshal.loads",
    }
    exec_targets = {
        "execl", "execle", "execlp", "execv", "execve", "execvp",
        "execvpe", "fexecve", "posix_spawn", "posix_spawnp",
        "CreateProcessA", "CreateProcessW",
        "CreateProcessAsUserA", "CreateProcessAsUserW",
        "CreateProcessWithLogonW",
    }

    if target in shell_targets:
        return "shell_execution"
    if target in code_exec_targets:
        return "code_execution"
    if target in deser_targets:
        return "deserialization"
    if target in exec_targets:
        return "process_execution"
    return "dangerous_call"
