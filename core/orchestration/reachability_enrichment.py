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
from typing import Any

from core.paths import path_to_module

logger = logging.getLogger(__name__)

# Native-language file suffixes: frida evidence only ever concerns
# compiled code, so enrichment skips non-native checklist entries.
_NATIVE_SUFFIXES = frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp",
    ".rs", ".go", ".s", ".S", ".asm",
})


def mark_unreachable_low_priority(
    checklist: dict[str, Any],
    target_path: Path,
    *,
    inventory: dict[str, Any] | None = None,
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
            import tempfile

            from core.inventory.builder import build_inventory
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


# ``packages/foo/bar.py`` → ``packages.foo.bar`` — the shared
# convention used by the codeql / validate consumers; one
# implementation in core.paths.
_path_to_module = path_to_module


# ---------------------------------------------------------------------------
# Caller-context enrichment — feed substrate-derived blast-radius data
# into the /agentic triage LLM's per-function context.
# ---------------------------------------------------------------------------


def _iter_enrichable_functions(files: list):
    """Yield ``(rel_path, func_dict)`` for caller-context candidates.

    Shared by the compute and apply walks so both sides use identical
    filters (function kind, non-low priority, named, positive line).
    """
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
            yield rel_path, func


def compute_caller_context(
    checklist: dict[str, Any],
    target_path: Path,
    *,
    inventory: dict[str, Any] | None = None,
    max_direct_caller_names: int = 5,
    max_depth: int = 20,
) -> dict[tuple[str, str, int], dict[str, Any]]:
    """Compute the caller-context fields WITHOUT mutating the checklist.

    Returns ``{(file_path, name, line_start): fields}`` where
    ``fields`` are the entries :func:`enrich_with_caller_context`
    writes. Split out so the expensive per-function reverse-closure
    walk can run against a lock-free snapshot; the cheap field
    application then happens under the checklist flock (a concurrent
    ``save_checklist`` writer must never block for the whole
    O(functions x closure) computation).
    """
    if not isinstance(checklist, dict):
        return {}
    files = checklist.get("files")
    if not isinstance(files, list):
        return {}

    if inventory is None:
        try:
            import tempfile

            from core.inventory.builder import build_inventory
            with tempfile.TemporaryDirectory() as td:
                inventory = build_inventory(str(target_path), td)
        except Exception as e:                          # noqa: BLE001
            logger.debug(
                "reachability_enrichment: inventory build failed (%s); "
                "skipping caller-context pass", e,
            )
            return {}

    try:
        from core.analysis.reachability import (
            InternalFunction,
            callers_of,
            reverse_closure,
        )
    except ImportError:
        return {}

    computed: dict[tuple[str, str, int], dict[str, Any]] = {}
    for rel_path, func in _iter_enrichable_functions(files):
        name = func["name"]
        line_start = func["line_start"]
        target = InternalFunction(
            file_path=rel_path, name=name, line=line_start,
        )
        try:
            one_hop = callers_of(inventory, target)
            closure = reverse_closure(
                inventory, target, max_depth=max_depth,
            )
        except Exception:
            logger.debug("reachability enrichment failed for %s", target, exc_info=True)
            continue

        direct_callers = one_hop.all_callers
        sorted_names = sorted(str(c) for c in direct_callers)
        computed[(rel_path, name, line_start)] = {
            "caller_count_direct": len(direct_callers),
            "caller_count_transitive": len(closure.nodes),
            "caller_count_uncertain": len(one_hop.uncertain),
            "direct_caller_names": sorted_names[:max_direct_caller_names],
        }
    return computed


def enrich_with_caller_context(
    checklist: dict[str, Any],
    target_path: Path,
    *,
    inventory: dict[str, Any] | None = None,
    max_direct_caller_names: int = 5,
    max_depth: int = 20,
    precomputed: dict[tuple[str, str, int], dict[str, Any]] | None = None,
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

    ``precomputed`` (from :func:`compute_caller_context` against a
    snapshot) skips the expensive closure walk here — used to keep
    that walk outside the checklist flock. Functions absent from the
    map (added or renamed after the snapshot) are simply not
    enriched, matching any pre-existing writer race.

    Returns the count of functions enriched.
    """
    if not isinstance(checklist, dict):
        return 0
    files = checklist.get("files")
    if not isinstance(files, list):
        return 0

    if precomputed is None:
        precomputed = compute_caller_context(
            checklist, target_path, inventory=inventory,
            max_direct_caller_names=max_direct_caller_names,
            max_depth=max_depth,
        )
    if not precomputed:
        return 0

    enriched = 0
    for rel_path, func in _iter_enrichable_functions(files):
        fields = precomputed.get(
            (rel_path, func["name"], func["line_start"]))
        if fields is None:
            continue
        for key, value in fields.items():
            # Fresh list per item: the map may be applied more than
            # once and persisted items must not alias each other.
            func[key] = list(value) if isinstance(value, list) else value
        enriched += 1

    if enriched:
        logger.debug(
            "reachability_enrichment: enriched %d function(s) with "
            "caller-context fields", enriched,
        )
    return enriched


def _native_name_collisions(files: list) -> dict[str, int]:
    """Count how many NATIVE files define each function name.

    C ``static`` functions routinely share names across translation
    units, and frida evidence joins on the bare function name — the
    join must know when a name is ambiguous so the un-executed twin
    never inherits unqualified "observed at runtime" evidence.
    """
    counts: dict[str, int] = {}
    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        fpath = file_entry.get("path", "")
        if not any(fpath.endswith(s) for s in _NATIVE_SUFFIXES):
            continue
        items = file_entry.get("items")
        if not isinstance(items, list):
            continue
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name", "")
            if isinstance(name, str) and name and name not in seen:
                seen.add(name)
                counts[name] = counts.get(name, 0) + 1
    return counts


def _evidence_names_file(ev: Any, fpath: str) -> bool:
    """True when a resolved callsite source sits in ``fpath``.

    Component-suffix compare (resolved paths are compile-dir absolute,
    checklist paths repo-relative) mirroring the callsite matcher in
    frida_validation_bridge.
    """
    for site in getattr(ev, "observed_callsites", None) or []:
        source = site.get("source") if isinstance(site, dict) else None
        if not isinstance(source, str) or ":" not in source:
            continue
        src_path = source.rsplit(":", 1)[0]
        if (src_path == fpath or src_path.endswith("/" + fpath)
                or fpath.endswith("/" + src_path)):
            return True
    return False


def enrich_with_frida_traces(
    checklist: dict[str, Any],
    target_path: Path,
    *,
    search_dirs: list | None = None,
    inventory: dict[str, Any] | None = None,
    evidence_map: dict | None = None,
) -> int:
    """Annotate checklist items with frida runtime-trace evidence.

    For each function in the checklist that was observed by frida at
    runtime, sets ``metadata.frida_runtime_trace`` on the item (and on
    the inventory item, if provided). Returns the count of items
    annotated.

    ``evidence_map`` (from ``collect_runtime_evidence``) skips the
    discovery walk here — used to keep the events.jsonl parses and
    sandboxed addr2line resolution outside the checklist flock.

    Best-effort: any failure returns 0 and the checklist is unchanged.
    """
    if evidence_map is None:
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


    files = checklist.get("files")
    if not isinstance(files, list):
        return 0

    def _trace_annotation(ev: Any, fn_name: str, fpath: str,
                          collisions: dict[str, int]) -> dict:
        annotation: dict[str, Any] = {
            "observed": True,
            "call_count": ev.call_count,
            "trace_id": ev.trace_id,
        }
        # The evidence join is by bare name. When the same name is
        # defined in more than one TU (classic C `static`) and the
        # evidence does not resolve a callsite into THIS file, the
        # observation may belong to the twin — mark it so consumers
        # (reach_witness promotion, Stage-B priority, prompts) can
        # discount instead of treating it as ground truth.
        if (collisions.get(fn_name, 0) > 1
                and not _evidence_names_file(ev, fpath)):
            annotation["name_only_match"] = True
        return annotation

    annotated = 0
    collisions = _native_name_collisions(files)
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
            meta["frida_runtime_trace"] = _trace_annotation(
                ev, fn_name, fpath, collisions)
            annotated += 1

    # Also annotate inventory items (dual-write) if provided.
    if inventory and isinstance(inventory, dict):
        inv_files = inventory.get("files")
        if isinstance(inv_files, list):
            inv_collisions = _native_name_collisions(inv_files)
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
                    meta["frida_runtime_trace"] = _trace_annotation(
                        ev, fn_name, fpath, inv_collisions)

    if annotated:
        logger.info(
            "reachability_enrichment: annotated %d function(s) with "
            "frida runtime-trace evidence", annotated,
        )
    return annotated


def _collect_frida_call_edges(
    search_dirs: list,
    target_path: str,
) -> dict[str, dict]:
    """Gather call-edge CALLEES from call-edges frida runs.

    Returns {callee_name: {"callers": [...], "call_count": n,
    "trace_id": run_dir}}. Ownership is enforced HOST-SIDE on top of
    the template's own filter (events come from inside the target
    process): the callee module must be the run's target binary or
    live under its directory.
    """
    try:
        from packages.frida import parse_events
        from packages.frida.evidence import discover_evidence
    except ImportError:
        return {}

    from pathlib import Path as _Path

    edges: dict[str, dict] = {}
    for ev in discover_evidence(
            [_Path(d) for d in search_dirs], target_path=target_path):
        if not ev.has_events or not ev.target_binary:
            continue
        target_name = _Path(ev.target_binary).name
        target_dir = str(_Path(ev.target_binary).parent)
        for record in parse_events(ev.run_dir / "events.jsonl"):
            if record.get("type") != "send":
                continue
            payload = record.get("payload")
            if not isinstance(payload, dict) or "_meta" in payload:
                continue
            if payload.get("category") != "call_edge":
                continue
            fn = payload.get("fn")
            if not isinstance(fn, str) or not fn:
                continue
            callee_module = payload.get("callee_module")
            callee_path = payload.get("callee_module_path")
            owned = callee_module == target_name or (
                isinstance(callee_path, str)
                and callee_path.startswith(target_dir + "/"))
            if not owned:
                continue
            entry = edges.setdefault(fn, {
                "callers": [], "call_count": 0,
                "trace_id": str(ev.run_dir),
            })
            count = payload.get("count")
            if not (isinstance(count, int) and 0 < count < 1_000_000_000):
                count = 1
            entry["call_count"] += count
            caller = payload.get("caller")
            if (isinstance(caller, str) and caller
                    and caller not in entry["callers"]
                    and len(entry["callers"]) < 8):
                entry["callers"].append(caller[:128])
    return edges


def collect_frida_call_edges(
    search_dirs: list,
    target_path: str,
) -> dict[str, dict]:
    """Public seam for pre-collecting call-edge evidence.

    Lets callers run the run-dir discovery walk outside any lock and
    hand the result to :func:`enrich_with_frida_call_edges` via
    ``edge_map``.
    """
    return _collect_frida_call_edges(search_dirs, target_path)


def enrich_with_frida_call_edges(
    checklist: dict[str, Any],
    target_path: Path,
    *,
    search_dirs: list | None = None,
    inventory: dict[str, Any] | None = None,
    edge_map: dict | None = None,
) -> int:
    """Annotate functions observed as call-edge CALLEES at runtime.

    Sets ``metadata.frida_call_edge`` on checklist (and inventory)
    items whose name appears as an owned callee in a call-edges frida
    run — the dynamic complement to the r2 binary_call_edge witness:
    an indirect call or vtable dispatch the static graph cannot
    resolve is ground truth here, because the call executed. Returns
    the count of annotated items. Best-effort: any failure returns 0.

    ``edge_map`` (from ``collect_frida_call_edges``) skips the
    discovery walk here — used to keep the run-dir scans outside the
    checklist flock.
    """
    if edge_map is None:
        if search_dirs is None:
            search_dirs = []
        try:
            edge_map = _collect_frida_call_edges(
                search_dirs, str(target_path))
        except Exception:  # noqa: BLE001 — enrichment is additive
            logger.debug("frida call-edge collection failed", exc_info=True)
            return 0
    if not edge_map:
        return 0

    def _annotate_items(files: list) -> int:
        n = 0
        collisions = _native_name_collisions(files)
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
                edge = edge_map.get(fn_name) if fn_name else None
                if edge is None:
                    continue
                meta = item.setdefault("metadata", {})
                annotation = {
                    "observed": True,
                    "call_count": edge["call_count"],
                    "callers": edge["callers"],
                    "trace_id": edge["trace_id"],
                }
                # Call-edge payloads carry no source resolution for
                # the callee, so a name defined in more than one TU
                # cannot be discriminated at all — mark every twin so
                # consumers can discount (the ground-truth claim in
                # this witness's contract holds only for unique
                # names).
                if collisions.get(fn_name, 0) > 1:
                    annotation["name_only_match"] = True
                meta["frida_call_edge"] = annotation
                n += 1
        return n

    annotated = 0
    files = checklist.get("files")
    if isinstance(files, list):
        annotated = _annotate_items(files)
    if inventory and isinstance(inventory, dict):
        inv_files = inventory.get("files")
        if isinstance(inv_files, list):
            _annotate_items(inv_files)

    if annotated:
        logger.info(
            "reachability_enrichment: annotated %d function(s) with "
            "frida call-edge evidence", annotated,
        )
    return annotated


__all__ = [
    "enrich_with_caller_context",
    "enrich_with_frida_call_edges",
    "enrich_with_frida_traces",
    "mark_unreachable_low_priority",
]
