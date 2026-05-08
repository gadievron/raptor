"""Reachability-driven checklist enrichment for /agentic.

Sibling of :func:`core.orchestration.understand_bridge.enrich_checklist`,
which marks entry-points and sinks as ``priority=high`` based on
the /understand context-map. This module marks dead-code
functions (NOT_CALLED verdict from
``core.inventory.reachability``) as ``priority=low`` so the
/agentic LLM analysis spends its budget on functions that
actually run.

The two enrichers are complementary:

  * ``enrich_checklist`` (understand_bridge): UPGRADES priority
    based on context-map data (entry points, sinks, trust
    boundaries).
  * ``mark_unreachable_low_priority`` (this module): DOWNGRADES
    priority for functions not reached from anywhere in non-test
    project source.

When both run, ``enrich_checklist`` should run FIRST so its
``priority=high`` markers stand. This module skips functions
already marked high-priority — the entry-point analysis trumps
reachability (a function might be an externally-callable entry
point that the project itself doesn't call internally; static
reachability would say NOT_CALLED but the operator still cares).

Mutates the checklist in place. Returns the count of functions
marked low-priority, mainly for diagnostic logging.

Best-effort: any failure (inventory build error, malformed
checklist, missing call_graph data) is logged at debug and the
checklist is returned unchanged.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def mark_unreachable_low_priority(
    checklist: Dict[str, Any],
    target_path: Path,
    *,
    inventory: Optional[Dict[str, Any]] = None,
) -> int:
    """Walk ``checklist["files"][*]["items"]`` and mark functions
    that are provably dead (NOT_CALLED) as ``priority="low"``.

    Skips functions already marked ``priority="high"`` —
    upstream enrichment (from /understand context-map) takes
    precedence. ``inventory`` may be passed in by the caller
    (avoids a redundant tree walk when a sibling consumer
    already built one).

    Returns the count of functions marked low-priority.
    """
    if not isinstance(checklist, dict):
        return 0
    files = checklist.get("files")
    if not isinstance(files, list):
        return 0

    if inventory is None:
        try:
            from core.inventory.builder import build_inventory
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                inventory = build_inventory(str(target_path), td)
        except Exception as e:                      # noqa: BLE001
            logger.debug(
                "reachability_enrichment: inventory build failed (%s); "
                "skipping low-priority pass", e,
            )
            return 0

    try:
        from core.inventory.reachability import (
            Verdict, function_called,
        )
    except ImportError:
        return 0

    marked = 0
    for file_info in files:
        if not isinstance(file_info, dict):
            continue
        rel_path = file_info.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            continue
        module = _path_to_module(rel_path)
        if not module:
            continue

        funcs = file_info.get("items")
        if not isinstance(funcs, list):
            funcs = file_info.get("functions")
        if not isinstance(funcs, list):
            continue

        for func in funcs:
            if not isinstance(func, dict):
                continue
            # Skip non-function items (globals, classes, macros).
            kind = func.get("kind")
            if kind and kind != "function":
                continue
            # Don't downgrade entries already marked high-priority
            # by upstream context-map enrichment.
            if func.get("priority") == "high":
                continue
            name = func.get("name")
            if not isinstance(name, str) or not name:
                continue

            qualified = f"{module}.{name}"
            try:
                result = function_called(inventory, qualified)
            except ValueError:
                continue
            if result.verdict != Verdict.NOT_CALLED:
                continue

            func["priority"] = "low"
            func["priority_reason"] = "reachability:not_called"
            marked += 1

    if marked:
        logger.info(
            "reachability_enrichment: marked %d function(s) as "
            "priority=low (not reached from non-test project source)",
            marked,
        )
    return marked


def _path_to_module(rel_path: str) -> Optional[str]:
    """``packages/foo/bar.py`` → ``packages.foo.bar``. Same
    convention used by the codeql / validate consumers."""
    if not rel_path:
        return None
    from pathlib import PurePosixPath
    p = PurePosixPath(rel_path.replace("\\", "/"))
    if not p.suffix:
        return None
    parts = list(p.with_suffix("").parts)
    if not parts:
        return None
    return ".".join(parts)


# ---------------------------------------------------------------------------
# Caller-context enrichment — feed substrate-derived blast-radius data
# into the /agentic triage LLM's per-function context.
# ---------------------------------------------------------------------------


def enrich_with_caller_context(
    checklist: Dict[str, Any],
    target_path: Path,
    *,
    inventory: Optional[Dict[str, Any]] = None,
    max_direct_caller_names: int = 5,
    max_depth: int = 20,
) -> int:
    """Walk ``checklist["files"][*]["items"]`` and attach
    substrate-derived caller context to each function.

    For each function, set:

      * ``caller_count_direct`` — 1-hop callers (definitive +
        uncertain + over-inclusive method match), via
        ``callers_of``.
      * ``caller_count_transitive`` — full reverse closure size.
      * ``caller_count_uncertain`` — file-masking-flag uncertain
        callers, surfaced separately because consumers may want
        to discount them.
      * ``direct_caller_names`` — first ``max_direct_caller_names``
        ``"file:name"`` strings, sorted, for the LLM's display.

    The /agentic triage prompt reads these alongside ``priority``
    so the LLM can judge blast radius — a function called by 50
    things has different stakes than one called by 1.

    Skips functions already marked ``priority="low"`` by
    ``mark_unreachable_low_priority`` — those are dead and the
    LLM will deprioritise them regardless.

    Returns the count of functions enriched.
    """
    if not isinstance(checklist, dict):
        return 0
    files = checklist.get("files")
    if not isinstance(files, list):
        return 0

    if inventory is None:
        try:
            from core.inventory.builder import build_inventory
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                inventory = build_inventory(str(target_path), td)
        except Exception as e:                          # noqa: BLE001
            logger.debug(
                "reachability_enrichment: inventory build failed (%s); "
                "skipping caller-context pass", e,
            )
            return 0

    try:
        from core.inventory.reachability import (
            InternalFunction,
            callers_of,
            reverse_closure,
        )
    except ImportError:
        return 0

    enriched = 0
    for file_info in files:
        if not isinstance(file_info, dict):
            continue
        rel_path = file_info.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            continue

        funcs = file_info.get("items")
        if not isinstance(funcs, list):
            funcs = file_info.get("functions")
        if not isinstance(funcs, list):
            continue

        for func in funcs:
            if not isinstance(func, dict):
                continue
            kind = func.get("kind")
            if kind and kind != "function":
                continue
            # Already-dead functions don't need caller context —
            # the LLM is going to deprioritise them anyway.
            if func.get("priority") == "low":
                continue
            name = func.get("name")
            if not isinstance(name, str) or not name:
                continue
            line_start = func.get("line_start")
            if not isinstance(line_start, int) or line_start <= 0:
                continue

            target = InternalFunction(
                file_path=rel_path, name=name, line=line_start,
            )
            try:
                one_hop = callers_of(inventory, target)
                closure = reverse_closure(
                    inventory, target, max_depth=max_depth,
                )
            except Exception:                          # noqa: BLE001
                continue

            direct_callers = one_hop.all_callers
            func["caller_count_direct"] = len(direct_callers)
            func["caller_count_transitive"] = len(closure.nodes)
            func["caller_count_uncertain"] = len(one_hop.uncertain)
            sorted_names = sorted(str(c) for c in direct_callers)
            func["direct_caller_names"] = (
                sorted_names[:max_direct_caller_names]
            )
            enriched += 1

    if enriched:
        logger.info(
            "reachability_enrichment: enriched %d function(s) with "
            "caller-context fields", enriched,
        )
    return enriched


__all__ = [
    "enrich_with_caller_context",
    "mark_unreachable_low_priority",
]
