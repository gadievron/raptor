"""Reachability-driven checklist enrichment for /agentic.

Sibling of :func:`core.orchestration.understand_bridge.enrich_checklist`,
which marks entry-points and sinks as ``priority=high`` based on
the /understand context-map. This module marks dead-code
functions (NOT_CALLED verdict from
``core.analysis.reachability``) as ``priority=low`` so the
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
    allow_unreachable: bool = False,
) -> int:
    """Walk ``checklist["files"][*]["items"]`` and mark functions
    that are provably dead (NOT_CALLED) as ``priority="low"``.

    Skips functions already marked ``priority="high"`` —
    upstream enrichment (from /understand context-map) takes
    precedence. ``inventory`` may be passed in by the caller
    (avoids a redundant tree walk when a sibling consumer
    already built one).

    ``allow_unreachable=True`` is the operator-opt-out for the
    in-isolation use case (CTF challenges, vendor reference
    snippets, exploit-research targets, intentional dead-code
    review). When set, NOT_CALLED functions do NOT receive the
    ``priority="low"`` demotion — the analysis prompt won't
    surface a "Verdict: NOT_CALLED" line, and the LLM is asked to
    evaluate the function's inherent vulnerability shape rather
    than its deployment reachability. Framework-callable /
    registered-via-call annotations are STILL applied (they're
    affirmative reachability evidence regardless of mode).

    Returns the count of functions marked low-priority. Zero when
    ``allow_unreachable=True`` (nothing demoted) but still mutates
    the checklist with framework_callable / registered_via_call
    annotations for functions that are *affirmatively* reachable. A
    framework handler shadowed by a whole-file dead witness (its file
    aborts on load / is build-excluded, or it's in an always-false
    guard) is NOT annotated framework-reachable — its registration
    never runs, so the dead witness wins even in isolation mode.
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
                # Union/raw view in isolation mode so the reachability
                # query graph matches the operator's declared intent
                # (review everything, incl. #if 0 code).
                inventory = build_inventory(
                    str(target_path), td,
                    allow_unreachable=allow_unreachable,
                )
        except Exception as e:                      # noqa: BLE001
            logger.debug(
                "reachability_enrichment: inventory build failed (%s); "
                "skipping low-priority pass", e,
            )
            return 0

    try:
        from core.analysis.reach_audit import classify_reachability
        from core.analysis.reach_witness import (
            Reachability,
            verdict_from_classification,
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

            line = int(func.get("line_start") or 0)

            # ONE entry-aware classifier — the same precedence the CodeQL
            # prefilter and /validate demoter use (module_aborts →
            # lexical_dead → build_excluded → framework / registration →
            # entry-reachability → 1-hop called/not_called). Single source of
            # truth; no parallel precedence chain here to drift out of sync.
            verdict = classify_reachability(
                inventory, rel_path, name, line, module,
            )
            if verdict_from_classification(verdict).status is (
                Reachability.UNREACHABLE
            ):
                # Surface-only soft-demote. allow_unreachable (the in-isolation
                # opt-out) skips the demotion so the analysis prompt emits no
                # dead-code verdict line. Covers module_aborts / lexical_dead /
                # build_excluded / no_path_from_entry / not_called uniformly.
                if allow_unreachable:
                    continue
                func["priority"] = "low"
                func["priority_reason"] = f"reachability:{verdict}"
                marked += 1
            elif verdict in ("framework_callable", "registered_via_call"):
                # Affirmative reachability evidence (framework dispatch /
                # function-as-argument registration) — annotate, never demote,
                # in both modes. (reachable / called / uncertain: leave as-is.)
                func["priority_reason"] = f"reachability:{verdict}"

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
        from core.analysis.reachability import (
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
                logger.debug("reachability enrichment failed for %s", target, exc_info=True)
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
        logger.debug(
            "reachability_enrichment: enriched %d function(s) with "
            "caller-context fields", enriched,
        )
    return enriched


def enrich_with_frida_traces(
    checklist: Dict[str, Any],
    target_path: Path,
    *,
    search_dirs: Optional[list] = None,
    inventory: Optional[Dict[str, Any]] = None,
) -> int:
    """Annotate checklist items with frida runtime-trace evidence.

    For each function in the checklist that was observed by frida at
    runtime, sets ``metadata.frida_runtime_trace`` on the item (and on
    the inventory item, if provided). Returns the count of items
    annotated.

    Best-effort: any failure returns 0 and the checklist is unchanged.
    """
    try:
        from core.orchestration.frida_validation_bridge import (
            collect_runtime_evidence,
        )
    except ImportError:
        return 0

    if search_dirs is None:
        search_dirs = []

    evidence_map = collect_runtime_evidence(
        [Path(d) for d in search_dirs], target_path=str(target_path))
    if not evidence_map:
        return 0

    _NATIVE_SUFFIXES = frozenset({
        ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp",
        ".rs", ".go", ".s", ".S", ".asm",
    })

    annotated = 0
    files = checklist.get("files")
    if not isinstance(files, list):
        return 0

    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        fpath = file_entry.get("path", "")
        if not any(fpath.endswith(s) for s in _NATIVE_SUFFIXES):
            continue
        items = file_entry.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            fn_name = item.get("name", "")
            if not fn_name:
                continue
            ev = evidence_map.get(fn_name)
            if ev is None:
                continue
            meta = item.setdefault("metadata", {})
            meta["frida_runtime_trace"] = {
                "observed": True,
                "call_count": ev.call_count,
                "trace_id": ev.trace_id,
            }
            annotated += 1

    # Also annotate inventory items (dual-write) if provided.
    if inventory and isinstance(inventory, dict):
        inv_files = inventory.get("files")
        if isinstance(inv_files, list):
            for file_entry in inv_files:
                if not isinstance(file_entry, dict):
                    continue
                fpath = file_entry.get("path", "")
                if not any(fpath.endswith(s) for s in _NATIVE_SUFFIXES):
                    continue
                inv_items = file_entry.get("items")
                if not isinstance(inv_items, list):
                    continue
                for item in inv_items:
                    if not isinstance(item, dict):
                        continue
                    fn_name = item.get("name", "")
                    ev = evidence_map.get(fn_name)
                    if ev is None:
                        continue
                    meta = item.setdefault("metadata", {})
                    meta["frida_runtime_trace"] = {
                        "observed": True,
                        "call_count": ev.call_count,
                        "trace_id": ev.trace_id,
                    }

    if annotated:
        logger.info(
            "reachability_enrichment: annotated %d function(s) with "
            "frida runtime-trace evidence", annotated,
        )
    return annotated


__all__ = [
    "enrich_with_caller_context",
    "enrich_with_frida_traces",
    "mark_unreachable_low_priority",
]
