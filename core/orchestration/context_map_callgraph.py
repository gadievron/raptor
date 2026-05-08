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
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


MAX_NAMES_PER_LIST = 10
DEFAULT_MAX_DEPTH = 10


def enrich_with_forward_reachable(
    context_map: Dict[str, Any],
    target_path: Path,
    *,
    inventory: Optional[Dict[str, Any]] = None,
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
        from core.inventory.reachability import (
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


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "MAX_NAMES_PER_LIST",
    "enrich_with_forward_reachable",
]
