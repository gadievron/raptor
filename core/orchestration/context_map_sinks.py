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

4. **Heuristic project sinks** — wrapper/naming/side-effect sinks from
   audit's sink-heuristics engine (``core.audit.sink_heuristics``),
   merged at HIGH/MEDIUM confidence with ``source: "heuristic"``.

5. **Macro-hidden sinks** — for C targets, the fidelity-3
   preprocessor-expanded view is scanned for dangerous calls invisible
   in source-as-written (allocator/lock wrappers hidden behind
   macros); merged with ``source: "mechanical-expanded"``.

6. **Audit-run discovered sinks** — a co-located or project-sibling
   audit run's ``discovered-sinks.json`` (whose taint-approx evidence
   the map-side heuristics cannot reproduce) is imported with
   ``source: "audit-heuristic"``.

Runs as MAP-5f after the normaliser and forward-reachable enrichment.
Idempotent — safe to re-run.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from core.inventory.sink_discovery import (
    SinkDiscoveryResult,
    discover_sinks_for_target,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 10
DEFAULT_FRAMEWORK_THRESHOLD = 5
DEFAULT_FRAMEWORK_MIN_FILES = 3
MAX_FRAMEWORK_APIS = 30

# Bounds for the fidelity-3 expanded-view sink scan.
EXPANDED_SINK_FILE_CAP = 20
EXPANDED_SINK_MAX_ADDED = 40
_C_SUFFIXES = (".c", ".cc", ".cpp", ".cxx")
# An ALL_CAPS macro invocation with arguments — the textual prefilter
# for "this file may hide calls behind macros".
_MACRO_CALL_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\s*\(")

# Only HIGH/MEDIUM heuristic discoveries enter the catalog — LOW is
# naming-only guesswork.
_HEURISTIC_CONFIDENCES = ("high", "medium")


def enrich_with_sink_discovery(
    context_map: dict[str, Any],
    target_path: Path,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    framework_threshold: int = DEFAULT_FRAMEWORK_THRESHOLD,
    framework_min_files: int = DEFAULT_FRAMEWORK_MIN_FILES,
    run_dir: Path | None = None,
    expand_macros: bool = True,
    extra_sinks: Any = None,
) -> int:
    """Enrich a context-map dict in place with sink discovery results.

    ``extra_sinks`` is an iterable of project-sink function names from
    the promoted IRIS taint-spec store (``core.iris.api.
    get_project_sinks``); they enter the catalog with ``source:
    "iris"`` provenance so flows through project-specific wrappers are
    visible to the map.

    Returns the number of entries enriched (sinks + entry points).
    """
    call_graphs: dict[str, Any] = {}
    result = discover_sinks_for_target(
        target_path,
        max_depth=max_depth,
        framework_threshold=framework_threshold,
        framework_min_files=framework_min_files,
        collect_call_graphs=call_graphs,
    )

    modified = 0

    # 1. Merge mechanically-discovered sinks into sink_details
    modified += _merge_discovered_sinks(context_map, result)

    # 2. Annotate entry points with reachable sinks
    modified += _annotate_entry_points(context_map, result)

    # 3. Add framework APIs to meta
    modified += _merge_framework_apis(context_map, result)

    # 4. Populate the simple `sinks` array for consumers that don't
    # read `sink_details` (e.g. audit orchestrator's sink-reachability gate)
    modified += _populate_sinks_array(context_map, result)

    # 5. Heuristic project sinks (audit's wrapper/naming/side-effect
    # discovery engine, run over the same call graphs)
    try:
        modified += _merge_heuristic_sinks(context_map, result, call_graphs)
    except Exception:
        logger.debug("heuristic sink merge failed", exc_info=True)

    # 6. Macro-hidden sinks from the fidelity-3 expanded view (C only)
    if expand_macros:
        try:
            modified += _merge_expanded_view_sinks(context_map, target_path)
        except Exception:
            logger.debug("expanded-view sink merge failed", exc_info=True)

    # 7. Import a sibling audit run's discovered sinks
    if run_dir is not None:
        try:
            modified += _import_audit_discovered_sinks(context_map, run_dir)
        except Exception:
            logger.debug("audit discovered-sinks import failed", exc_info=True)

    # 7b. Promoted IRIS taint-spec sinks (provenance: iris store)
    if extra_sinks:
        try:
            modified += _merge_iris_sinks(context_map, extra_sinks)
        except Exception:
            logger.debug("iris sink merge failed", exc_info=True)

    # 8. Add the summary to context_map root (always counts as modified
    # so the caller persists the result even if only framework APIs
    # or the summary changed)
    context_map["sink_discovery"] = result.as_dict()
    if result.direct_sinks or result.framework_apis:
        modified = max(modified, 1)

    return modified


def _merge_discovered_sinks(
    context_map: dict[str, Any],
    result: SinkDiscoveryResult,
) -> int:
    """Merge mechanically-discovered direct sinks into sink_details.

    Only adds sinks not already present (by file+line match).
    """
    sink_details = context_map.get("sink_details")
    if sink_details is None:
        sink_details = []
        context_map["sink_details"] = sink_details

    existing: set[tuple] = set()
    for sd in sink_details:
        if not isinstance(sd, dict):
            continue
        f = sd.get("file", "")
        line = sd.get("line") or 0
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
    context_map: dict[str, Any],
    result: SinkDiscoveryResult,
) -> int:
    """Add reachable_sinks to entry points that can reach dangerous sinks."""
    entry_points = context_map.get("entry_points", [])
    if not entry_points:
        return 0

    # Build lookup: (file, function) → sinks reachable
    reach_map: dict[tuple, list[str]] = {}
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
    context_map: dict[str, Any],
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
            existing_fw.add((fw.get("name") or "").lower())

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


def _populate_sinks_array(
    context_map: dict[str, Any],
    result: SinkDiscoveryResult,
) -> int:
    """Populate the simple ``sinks`` array from discovery results.

    The ``sinks`` array uses a flat format (file, function, target, direct)
    that consumers like the audit orchestrator's sink-reachability gate
    read directly.  Includes BOTH the caller function (which calls the
    dangerous target) AND the dangerous target itself — so any function
    that calls e.g. ``strcpy`` is transitively reachable to a sink.

    Merges with any existing ``sinks`` entries (e.g. from LLM MAP-3).
    Deduplicates by (file, function, target).
    """
    sinks = context_map.get("sinks")
    if sinks is None:
        sinks = []
        context_map["sinks"] = sinks

    existing: set[tuple] = set()
    for s in sinks:
        if not isinstance(s, dict):
            continue
        existing.add((s.get("file", ""), s.get("function", ""), s.get("target", "")))

    added = 0
    for sink in result.direct_sinks:
        key = (sink.file, sink.function, sink.target)
        if key not in existing:
            existing.add(key)
            sinks.append({
                "file": sink.file,
                "function": sink.function,
                "target": sink.target,
                "direct": sink.direct,
            })
            added += 1

        target_key = ("", sink.target, sink.target)
        if target_key not in existing:
            existing.add(target_key)
            sinks.append({
                "file": "",
                "function": sink.target,
                "target": sink.target,
                "direct": True,
            })
            added += 1

    if added:
        logger.info("sink enrichment: added %d entries to sinks array", added)
    return added


def _sink_detail_index(
    context_map: dict[str, Any],
) -> tuple:
    """(sink_details list, {(file, name)} and {(file, line)} dedup sets)."""
    sink_details = context_map.get("sink_details")
    if sink_details is None:
        sink_details = []
        context_map["sink_details"] = sink_details
    by_name: set[tuple] = set()
    by_line: set[tuple] = set()
    for sd in sink_details:
        if not isinstance(sd, dict):
            continue
        by_name.add((sd.get("file", ""), sd.get("name", "")))
        by_line.add((sd.get("file", ""), sd.get("line") or 0))
    return sink_details, by_name, by_line


def _append_flat_sink(
    context_map: dict[str, Any],
    *,
    file: str,
    function: str,
    target: str,
    direct: bool,
) -> None:
    """Append to the flat ``sinks`` array with dedup."""
    sinks = context_map.setdefault("sinks", [])
    for s in sinks:
        if isinstance(s, dict) and (
            s.get("file", ""), s.get("function", ""), s.get("target", ""),
        ) == (file, function, target):
            return
    sinks.append({
        "file": file,
        "function": function,
        "target": target,
        "direct": direct,
    })


def _merge_heuristic_sinks(
    context_map: dict[str, Any],
    result: SinkDiscoveryResult,
    call_graphs: dict[str, Any],
) -> int:
    """Merge audit's heuristic project-sink discoveries into the catalog.

    Runs ``core.audit.sink_heuristics.discover_project_sinks`` over the
    taxonomy result + call graphs and merges HIGH/MEDIUM-confidence
    wrapper/naming/side-effect sinks with ``source: "heuristic"``.
    """
    try:
        from core.audit.sink_heuristics import discover_project_sinks
    except ImportError:
        return 0

    heuristics = discover_project_sinks(result, call_graphs)
    if not heuristics.discovered:
        return 0

    sink_details, by_name, _ = _sink_detail_index(context_map)
    next_id = _next_sink_id(sink_details)
    added = 0
    for sink in heuristics.discovered:
        if sink.confidence not in _HEURISTIC_CONFIDENCES:
            continue
        key = (sink.file, sink.function)
        if key in by_name:
            continue
        wraps = ", ".join(sink.wraps) if sink.wraps else ""
        sink_details.append({
            "id": f"SINK-{next_id:03d}",
            "file": sink.file,
            "line": 0,
            "name": sink.function,
            "type": "project_sink",
            "dangerous_target": wraps,
            "source": "heuristic",
            "confidence": sink.confidence,
            "description": (
                f"Project sink wrapper: wraps {wraps} "
                f"({sink.caller_count} callers)"
                if wraps else
                f"Project sink ({sink.reason} heuristic, "
                f"{sink.caller_count} callers)"
            ),
        })
        _append_flat_sink(
            context_map,
            file=sink.file,
            function=sink.function,
            target=f"[project] {wraps}" if wraps else "[project]",
            direct=False,
        )
        by_name.add(key)
        next_id += 1
        added += 1

    if added:
        logger.info("sink enrichment: added %d heuristic project sinks", added)
    return added


def _merge_expanded_view_sinks(
    context_map: dict[str, Any],
    target_path: Path,
) -> int:
    """Catalog dangerous calls only visible after macro expansion.

    For C-family files carrying ALL_CAPS macro invocations, expand the
    translation unit at fidelity 3 and scan the expanded text for
    taxonomy sink calls whose originating source line does NOT show the
    call — allocator/lock wrappers hidden behind macros. Bounded
    (EXPANDED_SINK_FILE_CAP files, EXPANDED_SINK_MAX_ADDED entries);
    degrades silently when the preprocessor toolchain is unavailable.
    """
    try:
        from core.audit.preprocessor_view import expand_translation_unit
    except ImportError:
        return 0
    from core.inventory.sink_discovery import DANGEROUS_TARGETS

    c_targets = sorted(
        t for t in DANGEROUS_TARGETS if "." not in t and t.isidentifier()
    )
    if not c_targets:
        return 0
    call_re = re.compile(
        r"\b(" + "|".join(re.escape(t) for t in c_targets) + r")\s*\("
    )

    candidates: list[tuple] = []
    try:
        source_files = sorted(target_path.rglob("*"))
    except OSError:
        return 0
    for f in source_files:
        if len(candidates) >= EXPANDED_SINK_FILE_CAP:
            break
        if f.suffix not in _C_SUFFIXES or not f.is_file():
            continue
        try:
            raw = f.read_text(errors="replace")
        except OSError:
            continue
        if _MACRO_CALL_RE.search(raw):
            candidates.append((str(f.relative_to(target_path)), raw))

    if not candidates:
        return 0

    sink_details, _, by_line = _sink_detail_index(context_map)
    next_id = _next_sink_id(sink_details)
    raw_cache: dict[str, list[str] | None] = {
        rel: raw.splitlines() for rel, raw in candidates
    }
    added = 0

    for rel, _raw in candidates:
        if added >= EXPANDED_SINK_MAX_ADDED:
            break
        try:
            view = expand_translation_unit(
                target_path=target_path, file_path=rel,
            )
        except Exception:
            logger.debug("expansion failed for %s", rel, exc_info=True)
            continue
        if view is None or not view.ok:
            continue

        for idx, line in enumerate(view.lines(), start=1):
            if added >= EXPANDED_SINK_MAX_ADDED:
                break
            m = call_re.search(line)
            if not m:
                continue
            target = m.group(1)
            origin = view.origin_of(idx)
            if not origin:
                continue  # system header
            ofile, oline = origin
            orig_lines = _raw_lines_for(ofile, target_path, raw_cache)
            if orig_lines is None or not (0 < oline <= len(orig_lines)):
                continue
            if call_re.search(orig_lines[oline - 1]):
                continue  # visible in source-as-written — not macro-hidden
            if (ofile, oline) in by_line:
                continue
            sink_details.append({
                "id": f"SINK-{next_id:03d}",
                "file": ofile,
                "line": oline,
                "name": "",
                "type": _classify_sink_type(target),
                "dangerous_target": target,
                "source": "mechanical-expanded",
                "description": (
                    f"Calls {target} via macro expansion (fidelity-3 "
                    f"preprocessor view) — invisible in source-as-written"
                ),
            })
            _append_flat_sink(
                context_map,
                file="",
                function=target,
                target=target,
                direct=True,
            )
            by_line.add((ofile, oline))
            next_id += 1
            added += 1

    if added:
        logger.info(
            "sink enrichment: added %d macro-hidden sinks from the "
            "expanded view", added,
        )
    return added


def _raw_lines_for(
    rel: str,
    target_path: Path,
    cache: dict[str, list[str] | None],
) -> list[str] | None:
    if rel in cache:
        return cache[rel]
    lines: list[str] | None = None
    try:
        candidate = (target_path / rel).resolve()
        if str(candidate).startswith(str(target_path.resolve())) and candidate.is_file():
            lines = candidate.read_text(errors="replace").splitlines()
    except (OSError, ValueError):
        lines = None
    cache[rel] = lines
    return lines


def _import_audit_discovered_sinks(
    context_map: dict[str, Any],
    run_dir: Path,
) -> int:
    """Import an audit run's ``discovered-sinks.json`` into the catalog.

    Search order mirrors the cross-command bridges: co-located file
    first, then project siblings (``run_dir.parent``, newest first).
    Only HIGH/MEDIUM confidence discoveries are merged, with
    ``source: "audit-heuristic"`` provenance.
    """
    data = _find_discovered_sinks(run_dir)
    if not data:
        return 0

    sink_details, by_name, _ = _sink_detail_index(context_map)
    next_id = _next_sink_id(sink_details)
    added = 0
    for sink in data.get("discovered_sinks", []):
        if not isinstance(sink, dict):
            continue
        if sink.get("confidence") not in _HEURISTIC_CONFIDENCES:
            continue
        file = sink.get("file", "")
        name = sink.get("function", "")
        if not file or not name or (file, name) in by_name:
            continue
        wraps = ", ".join(sink.get("wraps", []) or [])
        sink_details.append({
            "id": f"SINK-{next_id:03d}",
            "file": file,
            "line": 0,
            "name": name,
            "type": "project_sink",
            "dangerous_target": wraps,
            "source": "audit-heuristic",
            "confidence": sink.get("confidence", ""),
            "description": (
                f"Audit-discovered project sink "
                f"({sink.get('reason', 'heuristic')}"
                + (f", wraps {wraps}" if wraps else "")
                + ")"
            ),
        })
        _append_flat_sink(
            context_map,
            file=file,
            function=name,
            target=f"[project] {wraps}" if wraps else "[project]",
            direct=False,
        )
        by_name.add((file, name))
        next_id += 1
        added += 1

    if added:
        logger.info(
            "sink enrichment: imported %d audit-discovered sinks", added,
        )
    return added


def _merge_iris_sinks(
    context_map: dict[str, Any],
    sink_names: Any,
) -> int:
    """Merge promoted IRIS taint-spec sinks into the catalog.

    Each name is a project-specific sink function from the persistent
    IRIS store; entries are marked ``source: "iris"``.
    """
    sink_details, by_name, _ = _sink_detail_index(context_map)
    known_names = {name for _file, name in by_name}
    next_id = _next_sink_id(sink_details)
    added = 0
    for fn in sorted(str(n) for n in sink_names if n):
        if fn in known_names:
            continue
        sink_details.append({
            "id": f"SINK-{next_id:03d}",
            "file": "",
            "line": 0,
            "name": fn,
            "type": "project_sink",
            "dangerous_target": fn,
            "source": "iris",
            "description": (
                "Promoted IRIS taint spec: project-specific sink"
            ),
        })
        _append_flat_sink(
            context_map, file="", function=fn, target=fn, direct=False,
        )
        known_names.add(fn)
        next_id += 1
        added += 1

    if added:
        logger.info("sink enrichment: added %d IRIS spec sinks", added)
    return added


def _find_discovered_sinks(run_dir: Path) -> dict[str, Any] | None:
    """Locate discovered-sinks.json: co-located, then project siblings."""
    candidates = [run_dir / "discovered-sinks.json"]
    parent = run_dir.parent
    try:
        if parent.is_dir():
            for sibling in sorted(parent.iterdir(), reverse=True):
                if sibling == run_dir or not sibling.is_dir():
                    continue
                candidates.append(sibling / "discovered-sinks.json")
    except OSError:
        pass

    for path in candidates:
        try:
            if not path.is_file():
                continue
            data = json.loads(path.read_text())
            if isinstance(data, dict) and data.get("discovered_sinks"):
                return data
        except (OSError, ValueError):
            continue
    return None


def _next_sink_id(sink_details: list) -> int:
    """Find the next available SINK-NNN id number."""
    max_id = 0
    for sd in sink_details:
        if not isinstance(sd, dict):
            continue
        sid = sd.get("id") or ""
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
