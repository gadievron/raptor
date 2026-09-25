"""Substrate-derived call-graph enrichment for /understand --map.

After ``/understand --map`` produces ``context-map.json`` (entry
points + sinks + trust boundaries), and after the normaliser runs,
this module enriches each entry point with the substrate's
forward-closure: the set of functions transitively reachable from
that entry. Operators reading the context map see machine-derived
"this entry point reaches N internal + M external functions, here's
the closure", which complements the LLM's narrative descriptions.

The enrichment is idempotent and best-effort: missing checklist /
inventory build failure / unresolved (file, line) entries leave
the entry point unchanged.

## Output shape

Each entry point dict gains a ``forward_reachable`` field:

    {
        "id": "EP-001",
        "file": "src/routes/query.py",
        "line": 34,
        ...,
        "forward_reachable": {
            "host": "src/routes/query.py:query_handler@34",
            "internal_count": 12,
            "external_count": 3,
            "internal_names": ["src/db/query.py:run_query@89", ...],
            "external_names": ["sqlite3.Cursor.execute", ...],
            "truncated": false
        }
    }

``internal_names`` / ``external_names`` are capped at
``MAX_NAMES_PER_LIST = 10`` to keep context-map.json readable.
``truncated`` flags when the closure walk hit ``max_depth`` —
operators can re-run with a higher depth or read it as "deep call
graph, partial enumeration".

## Why not flow-trace?

``/understand --trace`` produces ``flow-trace-*.json`` for
specific source→sink chains the operator picked. This enrichment
runs over EVERY entry point unconditionally, giving the next
consumer (``/diagram``, the audit prioritiser) a uniform view
without an operator picking traces.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# checklist.json tracks target size — the checklist budget class.
_MAX_CHECKLIST_BYTES = 256 * 1024 * 1024


MAX_NAMES_PER_LIST = 10
DEFAULT_MAX_DEPTH = 10

# Cap on call_edges materialised into context-map.json — the whole
# call graph x chain lengths previously landed unbounded (multi-MB
# maps on large targets, and every consumer re-walks the array).
# Sized above real large-target graphs; on hit the map is marked
# call_edges_truncated so negative reachability consumers degrade to
# inconclusive instead of reading a capped list as unreachability.
_MAX_CALL_EDGES = 200_000


def enrich_with_forward_reachable(
    context_map: dict[str, Any],
    target_path: Path,
    *,
    inventory: dict[str, Any] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_names_per_list: int = MAX_NAMES_PER_LIST,
) -> int:
    """Walk ``context_map["entry_points"]`` and attach a
    ``forward_reachable`` field to each entry's host function.

    ``inventory`` may be provided by the caller (avoids a redundant
    inventory build when a sibling consumer already constructed
    one). When omitted, builds one over ``target_path``.

    Returns the count of entries enriched. Idempotent — re-running
    overwrites prior enrichment with fresh data.
    """
    if not isinstance(context_map, dict):
        return 0
    entries = context_map.get("entry_points")
    if not isinstance(entries, list) or not entries:
        return 0

    if inventory is None:
        try:
            from core.inventory.builder import build_inventory
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                inventory = build_inventory(str(target_path), td)
        except Exception as e:                          # noqa: BLE001
            logger.debug(
                "context_map_callgraph: inventory build failed (%s); "
                "skipping enrichment", e,
            )
            return 0

    try:
        from core.analysis.reachability import (
            ExternalFunction,
            InternalFunction,
            enclosing_function,
            forward_closure,
        )
    except ImportError:
        return 0

    enriched_count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        file_path = entry.get("file") or entry.get("file_path")
        line = entry.get("line") or entry.get("line_start")
        if not isinstance(file_path, str) or not file_path:
            continue
        if not isinstance(line, int) or line <= 0:
            continue

        host = enclosing_function(inventory, file_path, line)
        if host is None:
            # Module-level entry, or path/line not in inventory.
            # Skip rather than emitting a placeholder — operators
            # would mistake a populated-but-empty enrichment for
            # "no callees" rather than "couldn't resolve host".
            continue

        try:
            closure = forward_closure(
                inventory, [host], max_depth=max_depth,
            )
        except Exception:                              # noqa: BLE001
            logger.debug("callgraph enrichment failed for %s", host, exc_info=True)
            continue

        internal_names: list = []
        external_names: list = []
        for node in closure.nodes:
            if isinstance(node, InternalFunction):
                internal_names.append(str(node))
            elif isinstance(node, ExternalFunction):
                external_names.append(str(node))
        internal_names.sort()
        external_names.sort()

        entry["forward_reachable"] = {
            "host": str(host),
            "internal_count": len(internal_names),
            "external_count": len(external_names),
            "internal_names": internal_names[:max_names_per_list],
            "external_names": external_names[:max_names_per_list],
            "truncated": closure.truncated,
        }
        enriched_count += 1

    if enriched_count:
        logger.info(
            "context_map_callgraph: enriched %d entry point(s) with "
            "forward-reachable closures", enriched_count,
        )
    return enriched_count


def _iter_checklist_call_edges(
    checklist: dict[str, Any],
    func_to_file: dict[str, str],
):
    """Yield every checklist call edge in the context-map
    ``call_edges`` dict shape. One walk order for the capped
    in-artifact list and the store routing, so both views derive from
    the same stream."""
    for fi in checklist.get("files", []):
        path = fi.get("path", "")
        cg = fi.get("call_graph")
        if not isinstance(cg, dict):
            continue
        for call in cg.get("calls", []):
            caller = call.get("caller", "")
            if not caller:
                continue
            for callee in call.get("chain", []):
                yield {
                    "caller_file": path,
                    "caller": caller,
                    "callee": callee,
                    "callee_file": func_to_file.get(callee, ""),
                }


def enrich_with_call_edges(
    context_map: dict[str, Any],
    checklist_path: Path | None = None,
    *,
    checklist: dict[str, Any] | None = None,
    graph_store: Path | None = None,
    run_dir: Path | None = None,
    target_path: str = "",
) -> int:
    """Add a ``call_edges`` array to the context map from checklist call graphs.

    Each edge is ``{"caller_file": ..., "caller": ..., "callee": ...}``.
    Consumers (sink-unreachability gate, /diagram) use this for transitive
    reachability without loading the full checklist separately.

    Provide either ``checklist_path`` (loaded from disk) or ``checklist``
    (pre-loaded dict).  Returns the number of edges added to the map.
    Idempotent — overwrites any prior ``call_edges``.

    Store routing (project mode): when ``graph_store``, ``run_dir`` and
    ``target_path`` are all given, the FULL mechanical edge set —
    uncapped — is additionally batch-ingested into the graph store
    (``core.understand_graph.ingest.ingest_call_edges``: lean rows,
    mechanical provenance, run-bound tokens) and the map gains a small
    ``call_edges_store`` marker (``{"snapshot", "edges"}``) that
    store-capable consumers resolve for reachability beyond the
    in-artifact cap. The capped in-artifact list is still written —
    it stays the storeless compatibility path, and the size-budget
    shed (``core.artifacts.context_map_budget``) already handles it on
    very large maps while the marker survives the shed.
    """
    if checklist is None:
        if checklist_path is None or not checklist_path.exists():
            return 0
        from core.json import load_json
        checklist = load_json(checklist_path, max_bytes=_MAX_CHECKLIST_BYTES)
        if not isinstance(checklist, dict):
            return 0

    func_to_file: dict[str, str] = {}
    for fi in checklist.get("files", []):
        path = fi.get("path", "")
        for item in fi.get("items", []):
            name = item.get("name", "")
            if name:
                func_to_file[name] = path

    route_to_store = (
        graph_store is not None and run_dir is not None and bool(target_path)
    )
    if graph_store is not None and not route_to_store:
        logger.debug(
            "context_map_callgraph: store routing skipped (graph_store "
            "given without run_dir/target_path)",
        )

    edges: list = []
    truncated = False
    for edge in _iter_checklist_call_edges(checklist, func_to_file):
        if len(edges) >= _MAX_CALL_EDGES:
            truncated = True
            break
        edges.append(edge)

    context_map["call_edges"] = edges
    # The marker rides the map so NEGATIVE consumers (the
    # precondition reachability walk) degrade to inconclusive rather
    # than reading a capped edge list as proof of unreachability.
    # Cleared on rebuild (idempotent overwrite) so a stale flag never
    # outlives the edge set it described. Same for the size-budget
    # shed marker (`call_edges_shed`, core.artifacts.context_map_budget)
    # and the store-routing marker (`call_edges_store`): a rebuild
    # replaces the shed payload / re-routes the store snapshot, so a
    # stale marker must not describe edges that are present again (or
    # a snapshot this rebuild superseded). Note the rebuild is only
    # durable if the map now fits its size budget — a re-save of a
    # still-over-budget map re-sheds.
    context_map.pop("call_edges_truncated", None)
    context_map.pop("call_edges_shed", None)
    context_map.pop("call_edges_store", None)

    stored: dict[str, Any] | None = None
    if route_to_store:
        try:
            from core.understand_graph.ingest import ingest_call_edges

            stored = ingest_call_edges(
                run_dir, target_path,
                _iter_checklist_call_edges(checklist, func_to_file),
                graph_path=graph_store,
            )
        except Exception:  # noqa: BLE001 — routing is additive; the artifact path must survive a broken store
            logger.debug(
                "context_map_callgraph: store routing failed", exc_info=True,
            )
            stored = None
        if stored:
            context_map["call_edges_store"] = {
                "snapshot": stored["snapshot"],
                "edges": stored["edges"],
            }
            logger.info(
                "context_map_callgraph: routed %d mechanical call edge(s) "
                "to the project graph store (%s)",
                stored["edges"],
                "stamped" if stored.get("stamped")
                else "unstamped — hint tier only",
            )

    if truncated:
        context_map["call_edges_truncated"] = True
        if stored:
            logger.warning(
                "context_map_callgraph: call-edge cap (%d) reached — "
                "in-artifact edge list truncated and marked; the full "
                "set (%d edges) is persisted in the project graph "
                "store, which store-capable consumers read; storeless "
                "negative reachability degrades to inconclusive",
                _MAX_CALL_EDGES, stored["edges"],
            )
        else:
            logger.warning(
                "context_map_callgraph: call-edge cap (%d) reached — edge "
                "list truncated and marked; negative reachability "
                "conclusions degrade to inconclusive. Remedy: run with an "
                "active project so the full edge set routes to the "
                "project graph store", _MAX_CALL_EDGES,
            )
    if edges:
        logger.info(
            "context_map_callgraph: added %d call edges from checklist",
            len(edges),
        )
    return len(edges)


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "MAX_NAMES_PER_LIST",
    "enrich_with_call_edges",
    "enrich_with_forward_reachable",
]
