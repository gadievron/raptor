"""Joern taint enrichment for `/validate` Stage B.

Two entry points, both optional and CPG-gated:

* :func:`enrich_attack_surface_with_taint` — before LLM reasoning
  begins, mechanically confirm which source → sink pairs in
  ``attack-surface.json`` have a dataflow-engine-verified taint flow.
  Confirmed sources gain ``has_taint_flow`` / ``taint_reaches_sinks``,
  sinks gain ``taint_reached_from``, and the surface root gains a
  ``taint_summary``. A ``has_taint_flow: true`` source is mechanical
  pre-confirmation for [B-3.1] input verification.

* :func:`confirm_finding_flow` — during [B-3.1], produce a full
  CPG-derived path trace for one finding (function parameters →
  sink call). The returned steps are tool output, satisfying GATE-6
  (PROOF). ``confirmed: true`` carries ``proximity_floor: 2`` — flow
  confirmed, mitigations unknown; ``confirmed: false`` is evidence,
  not proof of absence (bounded inter-procedural depth).

Function and call names are resolved from the attack-surface entries
plus the validation checklist (``files[].items`` line spans for the
enclosing function, ``files[].call_graph.calls`` for the callee at a
sink line). Pairs are capped at :data:`MAX_PAIRS`; the cap is recorded
in ``taint_summary`` rather than silently truncating. Idempotent —
prior taint annotations are cleared before re-annotating.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

logger = logging.getLogger(__name__)

MAX_PAIRS = 500

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_LOCATION_RE = re.compile(r"^\s*(\S+?):(\d+)")
_SOURCE_LOC_RE = re.compile(r"@\s*(\S+?):(\d+)\s*$")

_SOURCE_KEYS = ("has_taint_flow", "taint_reaches_sinks")
_SINK_KEYS = ("taint_reached_from",)


def _is_identifier(value: Any) -> bool:
    # fullmatch, not match — a $-anchored match() still admits a
    # trailing newline.
    return isinstance(value, str) and bool(_IDENTIFIER_RE.fullmatch(value))


def _first_call_name(text: Any) -> str | None:
    if not isinstance(text, str):
        return None
    m = _CALL_NAME_RE.search(text)
    return m.group(1) if m else None


def _same_file(a: str, b: str) -> bool:
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _function_spans(
    checklist: dict[str, Any] | None,
) -> list[tuple[str, str, int, int]]:
    """(file, function, line_start, line_end) from the checklist inventory."""
    spans: list[tuple[str, str, int, int]] = []
    if not isinstance(checklist, dict):
        return spans
    for f in checklist.get("files") or []:
        path = f.get("path")
        if not path:
            continue
        for item in f.get("items") or f.get("functions") or []:
            if item.get("kind") not in (None, "function"):
                continue
            name = item.get("name")
            start = item.get("line_start")
            if not name or not isinstance(start, int):
                continue
            end = item.get("line_end")
            spans.append((
                path, name, start,
                end if isinstance(end, int) else start,
            ))
    return spans


def _enclosing_function(
    spans: list[tuple[str, str, int, int]], file: str, line: int,
) -> str | None:
    best: tuple[int, str] | None = None
    for path, name, start, end in spans:
        if not _same_file(path, file):
            continue
        # Innermost wins (largest start ≤ line).
        if start <= line <= end and (best is None or start > best[0]):
            best = (start, name)
    return best[1] if best else None


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


def _lookup_call(
    calls: dict[tuple[str, int], str], file: str, line: int,
) -> str | None:
    if (file, line) in calls:
        return calls[(file, line)]
    for (path, call_line), callee in calls.items():
        if call_line == line and _same_file(path, file):
            return callee
    return None


def _source_location(source: dict[str, Any]) -> tuple[str, int] | None:
    m = _SOURCE_LOC_RE.search(source.get("entry") or "")
    return (m.group(1), int(m.group(2))) if m else None


def _source_method(
    source: dict[str, Any], spans: list[tuple[str, str, int, int]],
) -> str | None:
    """Resolve the function hosting a source entry."""
    fn = source.get("function")
    if _is_identifier(fn):
        return fn
    loc = _source_location(source)
    if loc:
        return _enclosing_function(spans, loc[0], loc[1])
    return None


def _sink_call_name(
    sink: dict[str, Any], calls: dict[tuple[str, int], str],
) -> str | None:
    """Resolve the callee name at a sink's location.

    ``location`` is ``file:line`` optionally followed by the sink code
    (``foo.c:6 — strcpy(...)``); the call graph wins over the parsed
    code snippet.
    """
    location = sink.get("location") or ""
    m = _LOCATION_RE.match(location)
    if m:
        callee = _lookup_call(calls, m.group(1), int(m.group(2)))
        if callee:
            return callee
    return _first_call_name(location) or _first_call_name(
        sink.get("operation"))


def _clear_prior_annotations(attack_surface: dict[str, Any]) -> None:
    for source in attack_surface.get("sources") or []:
        for key in _SOURCE_KEYS:
            source.pop(key, None)
    for sink in attack_surface.get("sinks") or []:
        for key in _SINK_KEYS:
            sink.pop(key, None)
    attack_surface.pop("taint_summary", None)


def _merge_iris_surface_entries(
    attack_surface: dict[str, Any],
    iris_dir: Any,
) -> tuple[int, int]:
    """Append promoted IRIS spec sources/sinks to the attack surface.

    Entries carry ``source_provenance: "iris"`` (sources) /
    ``"iris"`` in the sink's ``source`` field so downstream stages can
    see they came from the promoted spec store, not the LLM map.
    Idempotent: existing iris entries are reused, not duplicated.
    Returns (n_sources_added, n_sinks_added).
    """
    try:
        from core.iris.api import get_project_sinks, get_project_sources
    except ImportError:
        return (0, 0)

    iris_sources = get_project_sources(out_dir=iris_dir)
    iris_sinks = get_project_sinks(out_dir=iris_dir)
    if not iris_sources and not iris_sinks:
        return (0, 0)

    sources = attack_surface.setdefault("sources", [])
    sinks = attack_surface.setdefault("sinks", [])

    existing_sources = {
        s.get("entry", "") for s in sources if isinstance(s, dict)
    }
    existing_sinks = {
        s.get("location", "") for s in sinks if isinstance(s, dict)
    }

    n_sources = 0
    for fn in sorted(iris_sources):
        entry = f"iris:{fn}"
        if entry in existing_sources:
            continue
        sources.append({
            "type": "project_source",
            "entry": entry,
            "function": fn,
            "source_provenance": "iris",
            "description": (
                "Promoted IRIS taint spec: project-specific source"
            ),
        })
        n_sources += 1

    n_sinks = 0
    for fn in sorted(iris_sinks):
        location = f"iris:{fn}"
        if location in existing_sinks:
            continue
        sinks.append({
            "type": "project_sink",
            "location": location,
            "operation": f"{fn}(...)",
            "source": "iris",
            "description": (
                "Promoted IRIS taint spec: project-specific sink"
            ),
        })
        n_sinks += 1

    if n_sources or n_sinks:
        logger.info(
            "attack-surface: merged %d IRIS source(s), %d IRIS sink(s)",
            n_sources, n_sinks,
        )
    return (n_sources, n_sinks)


def enrich_attack_surface_with_taint(
    attack_surface: dict[str, Any],
    server: Any,
    checklist: dict[str, Any] | None = None,
    *,
    max_pairs: int = MAX_PAIRS,
    iris_dir: Any = None,
) -> int:
    """Annotate attack-surface.json with Joern taint confirmations.

    *server* is a started :class:`packages.joern.server.JoernServer`
    with the target's CPG already imported. When ``iris_dir`` (a run
    output dir) is given, promoted IRIS taint-spec sources and sinks
    join the surface (provenance-marked) so flows through
    project-specific wrappers are checked too. Returns the number of
    entries annotated (sources + sinks).
    """
    _clear_prior_annotations(attack_surface)

    iris_counts = (0, 0)
    if iris_dir is not None:
        try:
            iris_counts = _merge_iris_surface_entries(
                attack_surface, iris_dir,
            )
        except Exception:
            logger.debug("IRIS surface merge failed", exc_info=True)

    spans = _function_spans(checklist)
    calls = _call_index(checklist)

    pairs: list[tuple[dict[str, Any], dict[str, Any], str, str]] = []
    for source in attack_surface.get("sources") or []:
        source_method = _source_method(source, spans)
        if not _is_identifier(source_method) and source.get(
            "source_provenance"
        ) == "iris":
            # IRIS source entries name the function directly.
            source_method = source.get("function", "")
        if not _is_identifier(source_method):
            continue
        for sink in attack_surface.get("sinks") or []:
            sink_call = _sink_call_name(sink, calls)
            if not _is_identifier(sink_call):
                continue
            pairs.append((source, sink, source_method, sink_call))

    dropped = max(0, len(pairs) - max_pairs)
    if dropped:
        logger.warning(
            "attack-surface taint enrichment: %d pairs exceed cap of %d — "
            "dropping the excess", len(pairs), max_pairs,
        )
        pairs = pairs[:max_pairs]

    # Existence queries are per unique (source_method, sink_call);
    # multiple surface pairs can share one query.
    verdicts: dict[tuple[str, str], bool] = {}
    confirmed = 0
    for source, sink, source_method, sink_call in pairs:
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
        source["has_taint_flow"] = True
        reaches = source.setdefault("taint_reaches_sinks", [])
        sink_id = sink.get("location") or sink.get("type") or ""
        if sink_id and sink_id not in reaches:
            reaches.append(sink_id)
        reached = sink.setdefault("taint_reached_from", [])
        source_id = source.get("entry") or source.get("type") or ""
        if source_id and source_id not in reached:
            reached.append(source_id)

    sources_confirmed = [
        s.get("entry") or s.get("type")
        for s in attack_surface.get("sources") or []
        if s.get("has_taint_flow")
    ]
    sinks_confirmed = [
        s.get("location") or s.get("type")
        for s in attack_surface.get("sinks") or []
        if s.get("taint_reached_from")
    ]
    attack_surface["taint_summary"] = {
        "engine": "joern",
        "query": "exists",
        "pairs_checked": len(pairs),
        "pairs_dropped_over_cap": dropped,
        "flows_confirmed": confirmed,
        "sources_confirmed": sources_confirmed,
        "sinks_confirmed": sinks_confirmed,
        "iris_sources_loaded": iris_counts[0],
        "iris_sinks_loaded": iris_counts[1],
    }
    return len(sources_confirmed) + len(sinks_confirmed)


def _resolve_finding_sink(
    finding: dict[str, Any], calls: dict[tuple[str, int], str],
) -> str | None:
    proof = finding.get("proof")
    if isinstance(proof, dict):
        for field in ("sink", "vulnerable_code"):
            name = _first_call_name(proof.get(field))
            if name:
                return name
        if _is_identifier(proof.get("sink")):
            return proof["sink"]
    elif isinstance(proof, str):
        name = _first_call_name(proof)
        if name:
            return name

    file = finding.get("file")
    line = finding.get("line")
    if file and isinstance(line, int):
        return _lookup_call(calls, file, line)
    return None


def confirm_finding_flow(
    finding: dict[str, Any],
    server: Any,
    checklist: dict[str, Any] | None = None,
    *,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Produce a CPG-derived path trace for one finding ([B-3.1]).

    Source: the finding's host ``function`` (its parameters). Sink: the
    call named in ``proof.sink`` / ``proof.vulnerable_code``, falling
    back to the checklist call graph at the finding's ``file:line``.

    Returns a confirmation dict (also mirrored onto the finding as
    ``joern_flow_confirmation`` for the audit trail):

    * ``confirmed: true`` — full flow steps included; proximity floor 2.
    * ``confirmed: false`` — no flow found at bounded depth (evidence,
      not proof of absence).
    * ``confirmed: null`` — names unresolvable or query failed; the
      ``skipped`` field says why. No proximity effect.
    """
    source_method = finding.get("function")
    sink_call = _resolve_finding_sink(finding, _call_index(checklist))

    if not _is_identifier(source_method) or not _is_identifier(sink_call):
        missing = []
        if not _is_identifier(source_method):
            missing.append(f"source method ({source_method!r})")
        if not _is_identifier(sink_call):
            missing.append(f"sink call ({sink_call!r})")
        confirmation: dict[str, Any] = {
            "confirmed": None,
            "skipped": "could not resolve " + " and ".join(missing),
        }
        finding["joern_flow_confirmation"] = confirmation
        return confirmation

    start = time.monotonic()
    try:
        flows = server.run_taint_query(
            source_method, sink_call, timeout=timeout,
        ) or []
    except Exception:
        logger.debug(
            "taint query failed for %s -> %s",
            source_method, sink_call, exc_info=True,
        )
        confirmation = {
            "confirmed": None,
            "skipped": f"joern query failed for {source_method} -> {sink_call}",
        }
        finding["joern_flow_confirmation"] = confirmation
        return confirmation
    elapsed_ms = int((time.monotonic() - start) * 1000)

    confirmed = len(flows) > 0
    confirmation = {
        "confirmed": confirmed,
        "engine": "joern",
        "source_method": source_method,
        "sink_call": sink_call,
        "flow_count": len(flows),
        "steps": _flow_steps(flows[0]) if flows else [],
        "proximity_floor": 2 if confirmed else None,
        "elapsed_ms": elapsed_ms,
    }
    finding["joern_flow_confirmation"] = confirmation
    return confirmation


def _flow_steps(flow: Any) -> list[dict[str, Any]]:
    """Serialise one TaintFlow's steps for the confirmation record."""
    steps = getattr(flow, "steps", None) or []
    out = []
    for s in steps:
        if hasattr(s, "to_dict"):
            s = s.to_dict()
        if isinstance(s, dict):
            out.append({
                "file": s.get("file", ""),
                "line": s.get("line", 0),
                "code": s.get("code", ""),
                "function": s.get("function", ""),
            })
    return out
