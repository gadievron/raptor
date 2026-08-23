"""Enrich context-map.json with Joern taint-flow confirmation.

Runs as MAP-5i after the CPG cache build (MAP-5h). For each
entry-point × sink pair in the context map, asks Joern whether a
mechanically-verified taint flow exists from the entry point's host
function parameters to the sink's call site:

* entry points gain ``has_taint_flow`` and ``taint_reaches_sinks``
* sinks / sink_details gain ``taint_reached_from``
* the context map root gains a ``taint_summary``

Downstream, `/validate` Stage B imports ``has_taint_flow`` via the
understand bridge (which reads it from the top-level ``sources``
array, so confirmed entry points are mirrored there), and `/diagram`
renders confirmed flows as solid edges.

Pairs are capped at :data:`MAX_PAIRS` to prevent combinatorial
explosion; the cap is recorded in ``taint_summary`` rather than
silently truncating. Idempotent — prior taint annotations are cleared
before re-annotating.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

MAX_PAIRS = 500

_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SOURCE_LOC_RE = re.compile(r"@\s*(\S+?):(\d+)\s*$")

_EP_KEYS = ("has_taint_flow", "taint_reaches_sinks")
_SINK_KEYS = ("taint_reached_from",)


def _call_index(checklist: dict[str, Any] | None) -> dict[tuple[str, int], str]:
    """Map (file, line) -> callee name from the checklist call graph."""
    index: dict[tuple[str, int], str] = {}
    if not isinstance(checklist, dict):
        return index
    for f in checklist.get("files") or []:
        path = f.get("path")
        for call in (f.get("call_graph") or {}).get("calls") or []:
            chain = call.get("chain") or []
            line = call.get("line")
            if path and chain and isinstance(line, int):
                index[(path, line)] = chain[-1]
    return index


def _sink_call_name(
    sink: dict[str, Any], calls: dict[tuple[str, int], str],
) -> str | None:
    """Resolve the callee name at the sink's call site."""
    file, line = sink.get("file"), sink.get("line")
    if file and isinstance(line, int) and (file, line) in calls:
        return calls[(file, line)]
    m = _CALL_NAME_RE.search(sink.get("operation") or "")
    return m.group(1) if m else None


def build_taint_pairs(
    context_map: dict[str, Any],
    checklist: dict[str, Any] | None = None,
    *,
    iris_sinks: frozenset[str] = frozenset(),
) -> list[tuple[dict[str, Any], dict[str, Any], str, str]]:
    """Enumerate (entry_point, sink_detail, source_method, sink_call).

    ``iris_sinks`` holds promoted IRIS taint-spec sink function names:
    a sink detail whose call site can't be resolved from the call graph
    (typical for project-wrapper sinks, which carry name but no line)
    still pairs when its ``name`` is a known IRIS sink — the wrapper
    function itself is the callee. Such sinks are stamped
    ``taint_spec_source: "iris"`` for provenance.
    """
    calls = _call_index(checklist)
    pairs = []
    for ep in context_map.get("entry_points") or []:
        source_method = ep.get("name")
        if not source_method or not ep.get("id"):
            continue
        for sink in context_map.get("sink_details") or []:
            if not sink.get("id"):
                continue
            sink_call = _sink_call_name(sink, calls)
            if not sink_call:
                name = sink.get("name") or ""
                if name and name in iris_sinks:
                    sink_call = name
                    sink.setdefault("taint_spec_source", "iris")
                else:
                    continue
            pairs.append((ep, sink, source_method, sink_call))
    return pairs


def _clear_prior_annotations(context_map: dict[str, Any]) -> None:
    for ep in context_map.get("entry_points") or []:
        for key in _EP_KEYS:
            ep.pop(key, None)
    for sink in list(context_map.get("sink_details") or []) + list(
            context_map.get("sinks") or []):
        for key in _SINK_KEYS:
            sink.pop(key, None)
    for src in context_map.get("sources") or []:
        src.pop("has_taint_flow", None)
    context_map.pop("taint_summary", None)


def _mirror_to_sources(context_map: dict[str, Any], ep: dict[str, Any]) -> None:
    """Set has_taint_flow on the sources entry matching the entry point.

    The understand bridge reads ``has_taint_flow`` from the top-level
    ``sources`` array (the attack-surface schema), not entry_points.
    """
    for src in context_map.get("sources") or []:
        m = _SOURCE_LOC_RE.search(src.get("entry") or "")
        if not m:
            continue
        if m.group(1) == ep.get("file") and int(m.group(2)) == ep.get("line"):
            src["has_taint_flow"] = True


def _mirror_to_sinks(context_map: dict[str, Any], sink: dict[str, Any]) -> None:
    """Copy taint_reached_from to the matching top-level sinks entry."""
    location = f"{sink.get('file')}:{sink.get('line')}"
    for s in context_map.get("sinks") or []:
        if s.get("location") == location:
            s["taint_reached_from"] = list(sink.get("taint_reached_from") or [])


def enrich_with_taint_flows(
    context_map: dict[str, Any],
    server: Any,
    checklist: dict[str, Any] | None = None,
    *,
    max_pairs: int = MAX_PAIRS,
    iris_dir: Any = None,
) -> int:
    """Annotate the context map with Joern taint-flow confirmations.

    *server* is a started :class:`packages.joern.server.JoernServer`
    with the target's CPG already imported. When ``iris_dir`` (a run
    output dir) is given, promoted IRIS taint-spec sinks widen the
    pair enumeration so flows through project-specific wrappers are
    checked too. Returns the number of entries annotated (entry
    points + sinks).
    """
    _clear_prior_annotations(context_map)

    iris_sinks: frozenset[str] = frozenset()
    if iris_dir is not None:
        try:
            from core.iris.api import get_project_sinks

            iris_sinks = get_project_sinks(out_dir=iris_dir)
        except Exception:
            logger.debug("IRIS sink load failed", exc_info=True)

    pairs = build_taint_pairs(context_map, checklist, iris_sinks=iris_sinks)
    dropped = max(0, len(pairs) - max_pairs)
    if dropped:
        logger.warning(
            "taint enrichment: %d pairs exceed cap of %d — "
            "dropping the excess", len(pairs), max_pairs,
        )
        pairs = pairs[:max_pairs]

    # Existence queries are per unique (source_method, sink_call);
    # multiple map pairs can share one query.
    verdicts: dict[tuple[str, str], bool] = {}
    confirmed = 0
    for ep, sink, source_method, sink_call in pairs:
        key = (source_method, sink_call)
        if key not in verdicts:
            try:
                verdicts[key] = bool(
                    server.run_taint_exists_query(source_method, sink_call)
                )
            except Exception:
                logger.debug(
                    "taint exists query failed for %s -> %s",
                    source_method, sink_call, exc_info=True,
                )
                verdicts[key] = False
        if not verdicts[key]:
            continue
        confirmed += 1
        ep["has_taint_flow"] = True
        reaches = ep.setdefault("taint_reaches_sinks", [])
        if sink["id"] not in reaches:
            reaches.append(sink["id"])
        reached = sink.setdefault("taint_reached_from", [])
        if ep["id"] not in reached:
            reached.append(ep["id"])
        _mirror_to_sources(context_map, ep)
        _mirror_to_sinks(context_map, sink)

    eps_confirmed = [
        ep["id"] for ep in context_map.get("entry_points") or []
        if ep.get("has_taint_flow")
    ]
    sinks_confirmed = [
        s["id"] for s in context_map.get("sink_details") or []
        if s.get("taint_reached_from")
    ]
    context_map["taint_summary"] = {
        "engine": "joern",
        "query": "exists",
        "pairs_checked": len(pairs),
        "pairs_dropped_over_cap": dropped,
        "flows_confirmed": confirmed,
        "entry_points_confirmed": eps_confirmed,
        "sinks_confirmed": sinks_confirmed,
        "iris_sinks_loaded": len(iris_sinks),
    }
    return len(eps_confirmed) + len(sinks_confirmed)
