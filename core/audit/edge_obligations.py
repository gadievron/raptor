"""Edge-obligation scoping pass — which call edges MUST be reviewed.

Function coverage says "every function was looked at"; bugs live in
the interactions — A trusts B's return, B assumes A validated its
input. An unreviewed edge between two reviewed functions is an
unreviewed trust assumption. This pass intersects the checklist's
per-file call graphs with the context-map to emit the bounded set of
edges whose trust contract needs a review, tiered for the hybrid
review model:

* ``tier1`` — edges incident to a trust-boundary function (the
  function containing a ``trust_boundaries[].check`` site). Reviewed
  as dedicated work units with both endpoint bodies in context.
* ``tier2`` — other edges on a source→sink path (caller in the
  forward closure from entry-point functions AND callee in the
  reverse closure from sink functions). Reviewed as folded
  ``edge_verdicts`` inside the caller's function review.

There is deliberately NO global edge-coverage percentage. The second
first-class output is the ``blind_spots`` list: call sites on attack
paths the static graph cannot follow (function pointers / dynamic
dispatch via the extractor's ``indirection`` set, ``getattr`` string
dispatch, unresolved or ambiguous callee names). You cannot take a
percentage over edges you cannot enumerate, so they are surfaced
loudly instead of silently excluded. A callee name with MULTIPLE
inventory definitions (CHA-style dispatch) is one ``ambiguous_callee``
blind-spot row, never a fan-out of N phantom obligations.

Deterministic, no LLM. Output ``edge-obligations.json`` is a derived,
rebuildable artifact — it lives in the run directory, not the
coverage store. Every drop is counted in ``stats`` (no silent caps).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from core.coverage.edges import (
    parse_loc,
    normalise_trace_path,
    containing_item,
    item_spans,
    load_touched,
)
from core.json import save_json

logger = logging.getLogger(__name__)

EDGE_OBLIGATIONS_FILENAME = "edge-obligations.json"

Node = tuple  # (file, name)


def _normalise_type(name: str) -> str:
    """Receiver type → bare type name (strip qualifiers/pointers)."""
    out = name.strip()
    for tok in ("const ", "struct ", "class ", "enum "):
        out = out.replace(tok, "")
    return out.strip(" *&").strip()


def _resolve_dispatch(
    call: dict,
    caller: str,
    tail: str,
    candidate_paths: list,
    items_by_file: dict,
) -> tuple | None:
    """Disambiguate a multi-definition callee (CHA dispatch site).

    Two mechanical witnesses, tried most-specific first; a site
    resolves only when EXACTLY ONE candidate matches — anything less
    certain stays an ``ambiguous_callee`` blind spot:

    * typed dispatch — the call carries ``receiver_type`` /
      ``receiver_class`` and exactly one candidate file defines a
      class of that name whose span contains a same-named callee;
    * binary edge — exactly one candidate's item carries a
      ``metadata.binary_oracle_edges`` entry naming THIS caller
      (the linker admitted one definition; the r2 edge names it).

    Returns ``(definition_file, how)`` or ``None``.
    """
    recv = call.get("receiver_type") or call.get("receiver_class")
    if recv:
        recv = _normalise_type(str(recv))
        matches = []
        for path in candidate_paths:
            items = items_by_file.get(path) or []
            classes = [
                it for it in items
                if it.get("kind") == "class" and it.get("name") == recv
            ]
            for cls in classes:
                lo = cls.get("line_start") or 0
                hi = cls.get("line_end") or lo
                if any(
                    it.get("name") == tail
                    and lo <= (it.get("line_start") or -1) <= hi
                    for it in items
                ):
                    matches.append(path)
                    break
        if len(matches) == 1:
            return (matches[0], "typed")

    matches = []
    for path in candidate_paths:
        for it in items_by_file.get(path) or []:
            if it.get("name") != tail:
                continue
            md = it.get("metadata") or {}
            for be in md.get("binary_oracle_edges") or []:
                if isinstance(be, dict) and be.get("caller") == caller:
                    matches.append(path)
                    break
            else:
                continue
            break
    if len(matches) == 1:
        return (matches[0], "binary")
    return None


def _name_definitions(checklist: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for fe in checklist.get("files", []) or []:
        path = fe.get("path")
        if not path:
            continue
        for it in fe.get("items", fe.get("functions", [])) or []:
            name = it.get("name")
            if name:
                paths = out.setdefault(name, [])
                if path not in paths:
                    paths.append(path)
    return out


def _anchor_nodes(
    entries: list, spans: dict, inv_paths: set,
) -> set[Node]:
    """Resolve context-map records carrying ``file``+``line`` (or a
    ``location``/``check`` ``file:line`` string) to inventory nodes."""
    nodes: set[Node] = set()
    for rec in entries or []:
        if not isinstance(rec, dict):
            continue
        f, ln = rec.get("file"), rec.get("line")
        if not (isinstance(f, str) and isinstance(ln, int)):
            loc = parse_loc(rec.get("location") or rec.get("check"))
            if loc is None:
                continue
            f, ln = loc
        path = normalise_trace_path(f, inv_paths)
        if not path:
            continue
        name = containing_item(spans, path, ln)
        if name:
            nodes.add((path, name))
    return nodes


def _closure(seeds: set[Node], adj: dict[Node, set]) -> set[Node]:
    seen = set(seeds)
    frontier = list(seeds)
    while frontier:
        node = frontier.pop()
        for nxt in adj.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    return seen


def build_edge_obligations(
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    *,
    touched: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute the tiered obligation set + blind-spot list.

    Degrades honestly: without a context-map (or without resolvable
    boundary/entry/sink anchors) the affected tier is empty and the
    condition is named in ``stats.degraded`` — an empty obligation set
    must be distinguishable from "everything reviewed".
    """
    spans = item_spans(checklist)
    inv_paths = set(spans)
    defs = _name_definitions(checklist)
    cm = context_map if isinstance(context_map, dict) else {}
    degraded: list[str] = []
    if not cm:
        degraded.append("no-context-map")

    boundary_label: dict[Node, str] = {}
    for tb in cm.get("trust_boundaries") or []:
        if not isinstance(tb, dict):
            continue
        loc = parse_loc(tb.get("check"))
        if loc is None:
            continue
        path = normalise_trace_path(loc[0], inv_paths)
        if not path:
            continue
        name = containing_item(spans, path, loc[1])
        if name:
            boundary_label.setdefault(
                (path, name), str(tb.get("boundary") or "unnamed"))

    entry_nodes = _anchor_nodes(cm.get("entry_points"), spans, inv_paths)
    sink_nodes = _anchor_nodes(cm.get("sinks"), spans, inv_paths)
    sink_nodes |= _anchor_nodes(cm.get("sink_details"), spans, inv_paths)
    if cm and not boundary_label:
        degraded.append("no-boundary-anchors")
    if cm and (not entry_nodes or not sink_nodes):
        degraded.append("no-path-anchors")

    # Resolved adjacency from the checklist's per-file call graphs.
    edges: list[tuple] = []          # (cfile, caller, efile, callee, line)
    seen_edges: set[tuple] = set()
    unresolved: list[tuple] = []     # (file, caller, name)
    ambiguous: list[tuple] = []
    dispatch_how: dict[tuple, str] = {}   # (cfile,caller,efile,callee) -> witness
    items_by_file = {
        fe.get("path"): (fe.get("items") or fe.get("functions") or [])
        for fe in checklist.get("files", []) or []
    }
    for fe in checklist.get("files", []) or []:
        path = fe.get("path")
        cg = fe.get("call_graph")
        if not path or not isinstance(cg, dict):
            continue
        for call in cg.get("calls") or []:
            if not isinstance(call, dict):
                continue
            chain = call.get("chain") or []
            tail = chain[-1] if chain else None
            line = call.get("line")
            caller = call.get("caller")
            if not caller and isinstance(line, int):
                caller = containing_item(spans, path, line)
            if not caller or not tail:
                continue             # module-level / unnamed callee
            paths = defs.get(tail) or []
            if len(paths) == 1:
                key = (path, caller, paths[0], tail, line)
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append(key)
            elif not paths:
                unresolved.append((path, caller, tail))
            else:
                resolved = _resolve_dispatch(
                    call, caller, tail, paths, items_by_file)
                if resolved is not None:
                    efile, how = resolved
                    key = (path, caller, efile, tail, line)
                    if key not in seen_edges:
                        seen_edges.add(key)
                        edges.append(key)
                        dispatch_how[(path, caller, efile, tail)] = how
                else:
                    ambiguous.append((path, caller, tail))

    fwd: dict[Node, set] = {}
    rev: dict[Node, set] = {}
    for cfile, caller, efile, callee, _line in edges:
        fwd.setdefault((cfile, caller), set()).add((efile, callee))
        rev.setdefault((efile, callee), set()).add((cfile, caller))
    reach_from_entries = _closure(entry_nodes, fwd)
    reach_to_sinks = _closure(sink_nodes, rev)
    on_path_nodes = reach_from_entries & reach_to_sinks

    touched_keys = {
        (e.get("caller_file"), e.get("caller"),
         e.get("callee_file"), e.get("callee"))
        for e in touched or []
    }

    def _record(cfile, caller, efile, callee, line, reason):
        return {
            "caller_file": cfile, "caller": caller,
            "callee_file": efile, "callee": callee,
            "call_line": line, "reason": reason,
            "touched": (cfile, caller, efile, callee) in touched_keys,
        }

    tier1: list[dict] = []
    tier2: list[dict] = []
    for cfile, caller, efile, callee, line in edges:
        caller_node, callee_node = (cfile, caller), (efile, callee)
        label = boundary_label.get(caller_node) or boundary_label.get(
            callee_node)
        how = dispatch_how.get((cfile, caller, efile, callee))
        if label is not None:
            tier1.append(_record(
                cfile, caller, efile, callee, line, f"boundary:{label}"))
        elif (how is not None
                and caller_node in reach_from_entries
                and callee_node in reach_to_sinks):
            # A resolved dispatch site ON AN ATTACK PATH is one
            # obligation reviewed as a dedicated unit (2026-05-29
            # design: dispatch reaches contract_ok only when the
            # realizable target is explicitly accounted for) — the
            # mechanical witness names the target. Resolved sites off
            # the attack path still join the adjacency (improving both
            # closures) but carry no paid obligation: promoting every
            # resolved dispatch edge would balloon dedicated-unit cost
            # on dispatch-heavy codebases far beyond the design's
            # attack-path scoping.
            tier1.append(_record(
                cfile, caller, efile, callee, line, f"dispatch:{how}"))
        elif (caller_node in reach_from_entries
                and callee_node in reach_to_sinks):
            tier2.append(_record(
                cfile, caller, efile, callee, line, "on-path"))

    # Blind spots: what the static graph cannot follow, restricted to
    # attack-path relevance. Relevance = REACHABLE FROM AN ENTRY POINT
    # (not fully on-path): an unfollowable call site is exactly why
    # sink-reachability can't be established for its caller, so
    # requiring on-path membership would filter out the very rows the
    # report exists to surface.
    reachable_files = {f for f, _ in reach_from_entries}
    blind: list[dict] = []
    seen_blind: set[tuple] = set()

    def _blind(file, caller, kind, name) -> None:
        key = (file, caller, kind, name)
        if key in seen_blind:
            return
        seen_blind.add(key)
        blind.append({"file": file, "caller": caller,
                      "kind": kind, "name": name})

    for fe in checklist.get("files", []) or []:
        path = fe.get("path")
        cg = fe.get("call_graph")
        if (not path or not isinstance(cg, dict)
                or path not in reachable_files):
            continue
        for name in cg.get("indirection") or []:
            _blind(path, None, "indirection", name)
        for name in cg.get("getattr_targets") or []:
            _blind(path, None, "getattr", name)
    for path, caller, name in unresolved:
        if (path, caller) in reach_from_entries:
            _blind(path, caller, "unresolved_callee", name)
    for path, caller, name in ambiguous:
        if (path, caller) in reach_from_entries:
            _blind(path, caller, "ambiguous_callee", name)

    return {
        "schema_version": 1,
        "tier1": tier1,
        "tier2": tier2,
        "blind_spots": blind,
        "stats": {
            "dispatch_resolved": len(dispatch_how),
            "edges_total": len(edges) + len(unresolved) + len(ambiguous),
            "resolved": len(edges),
            "unresolved": len(unresolved),
            "ambiguous": len(ambiguous),
            "boundary_functions": len(boundary_label),
            "entry_functions": len(entry_nodes),
            "sink_functions": len(sink_nodes),
            "on_path_functions": len(on_path_nodes),
            "degraded": degraded,
        },
    }


def write_edge_obligations(run_dir: Path, payload: dict[str, Any]) -> Path:
    """Persist ``edge-obligations.json`` (idempotent overwrite)."""
    path = Path(run_dir) / EDGE_OBLIGATIONS_FILENAME
    save_json(path, payload)
    return path


def build_and_write(
    run_dir: Path,
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    extra_degraded: list[str] | None = None,
) -> dict[str, Any]:
    """Scope + persist for a run dir, folding in its touched edges.

    ``extra_degraded`` lets the caller record run-level degradations
    the scoping pass itself cannot see (e.g. ``no-domain-model``) in
    the same ``stats.degraded`` channel — one place for every
    honesty-of-coverage note.
    """
    payload = build_edge_obligations(
        checklist, context_map, touched=load_touched(Path(run_dir)))
    for reason in extra_degraded or []:
        if reason not in payload["stats"]["degraded"]:
            payload["stats"]["degraded"].append(reason)
    write_edge_obligations(Path(run_dir), payload)
    return payload
