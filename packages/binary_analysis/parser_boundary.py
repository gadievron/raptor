"""Recover narrow parser-boundary candidates behind binary ingress.

The operator-facing problem is not "does this binary import a parser?" but
"which internal function behind an externally drivable ingress is the narrow
boundary worth tracing or harnessing?". This module answers that with bounded
call-graph paths only:

- ingress must already be recovered and bound to a function
- the internal path must come from radare2 call-graph edges
- the candidate function must directly call a parser surface
- runtime parser callsites may strengthen the candidate, but are not required

The result is still a candidate, not a finding and not a trusted harness ABI.
"""

from __future__ import annotations

import hashlib
from collections import deque
from typing import Any

from core.evidence import EvidenceRecord, EvidenceTier, make_evidence

_MAX_PATH_DEPTH = 6


def _addr(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, int):
        return hex(v)
    return str(v)


def _id(*parts: Any) -> str:
    raw = "::".join(str(part) for part in parts)
    return f"BPARSER-{hashlib.sha256(raw.encode('utf-8', 'surrogateescape')).hexdigest()[:12]}"


def _path_id(*parts: Any) -> str:
    raw = "::".join(str(part) for part in parts)
    return f"BPATH-{hashlib.sha256(raw.encode('utf-8', 'surrogateescape')).hexdigest()[:12]}"


def _function_map(context_map: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("id") or ""): item
        for item in context_map.get("interesting_functions", [])
        if isinstance(item, dict) and item.get("id")
    }


def _surface_map(context_map: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("id") or ""): item
        for item in context_map.get("surface_details", [])
        if isinstance(item, dict) and item.get("id")
    }


def extract_parser_boundaries(
    *,
    binary_sha256: str,
    binary_path: str,
    context_map: dict[str, Any],
    max_depth: int = _MAX_PATH_DEPTH,
) -> tuple[list[dict[str, Any]], list[EvidenceRecord]]:
    """Return xref-backed parser boundary candidates for recovered ingress."""
    functions = _function_map(context_map)
    surfaces = _surface_map(context_map)
    parser_surface_ids = {
        surface_id
        for surface_id, item in surfaces.items()
        if item.get("category") == "parser"
    }
    if not parser_surface_ids:
        return [], []

    internal_edges: dict[str, list[dict[str, Any]]] = {}
    parser_calls: dict[str, list[dict[str, Any]]] = {}
    for edge in context_map.get("call_graph_edges", []):
        if not isinstance(edge, dict):
            continue
        source_id = str(edge.get("source_function") or "")
        target_function = str(edge.get("target_function") or "")
        target_surface = str(edge.get("target_surface") or "")
        if source_id and target_function:
            internal_edges.setdefault(source_id, []).append(edge)
        if source_id and target_surface in parser_surface_ids:
            parser_calls.setdefault(source_id, []).append(edge)

    runtime_parser_by_function: dict[str, list[dict[str, Any]]] = {}
    for flow in context_map.get("runtime_parser_flows", []):
        if not isinstance(flow, dict):
            continue
        function_id = str(flow.get("function_id") or "")
        if function_id:
            runtime_parser_by_function.setdefault(function_id, []).append(flow)

    candidates: list[dict[str, Any]] = []
    records: list[EvidenceRecord] = []
    seen: set[tuple[str, str]] = set()
    for ingress in context_map.get("external_ingress_candidates", []):
        if not isinstance(ingress, dict):
            continue
        ingress_id = str(ingress.get("id") or "")
        start_id = str(ingress.get("bound_function_id") or "")
        if start_id not in functions:
            ingress_address = _addr(ingress.get("address"))
            ingress_name = str(ingress.get("bound_function_name") or ingress.get("name") or "")
            start_id = next(
                (
                    function_id
                    for function_id, item in functions.items()
                    if (
                        ingress_address
                        and _addr(item.get("address")) == ingress_address
                    ) or (
                        ingress_name
                        and str(item.get("name") or "") == ingress_name
                    )
                ),
                "",
            )
        if not ingress_id or not start_id or start_id not in functions:
            continue

        # Dynamic dispatch can hide the static edge in Swift/ObjC code. When a
        # runtime parser callsite carries a target-module backtrace that also
        # contains the recovered ingress function, that is enough to recover a
        # runtime-backed boundary candidate without pretending static taint.
        for runtime_flow in context_map.get("runtime_parser_flows", []):
            if not isinstance(runtime_flow, dict):
                continue
            boundary_id = str(runtime_flow.get("function_id") or "")
            backtrace_ids = [
                str(item) for item in runtime_flow.get("backtrace_function_ids", [])
                if item
            ]
            if boundary_id not in functions or start_id not in backtrace_ids:
                continue
            key = (ingress_id, boundary_id)
            if key in seen:
                continue
            seen.add(key)
            parser_surface = surfaces.get(str(runtime_flow.get("parser_surface_id") or ""))
            if parser_surface is None:
                continue
            if boundary_id in backtrace_ids:
                boundary_index = backtrace_ids.index(boundary_id)
                ingress_index = backtrace_ids.index(start_id)
                if boundary_index <= ingress_index:
                    path = list(reversed(backtrace_ids[boundary_index:ingress_index + 1]))
                else:
                    path = backtrace_ids[ingress_index:boundary_index + 1]
            else:
                path = [start_id, boundary_id]
            path = [item for item in path if item in functions]
            if not path:
                path = [start_id, boundary_id]
            path_names = [str(functions[item].get("name") or item) for item in path]
            function = functions[boundary_id]
            record = make_evidence(
                binary_sha256,
                kind="parser_boundary_candidate",
                source="frida_parser_backtrace",
                summary=(
                    f"Runtime parser backtrace linked ingress {ingress.get('name')!r} "
                    f"to parser boundary {function.get('name')!r}"
                ),
                tier=EvidenceTier.OBSERVED_RUNTIME,
                confidence="confirmed",
                reproducible=False,
                tool="frida",
                location=f"{binary_path}@{function.get('address') or ''}",
                data={
                    "ingress_id": ingress_id,
                    "boundary_function_id": boundary_id,
                    "parser_surface_id": parser_surface.get("id"),
                    "path_function_ids": path,
                    "path_function_names": path_names,
                    "depth": max(0, len(path) - 1),
                    "runtime_parser_flows": [runtime_flow.get("id")],
                },
            )
            records.append(record)
            evidence_ids = [
                *list(ingress.get("evidence_ids") or []),
                record.id,
                *list(runtime_flow.get("evidence_ids") or []),
            ]
            candidates.append({
                "id": _id(ingress_id, boundary_id, parser_surface.get("id")),
                "ingress_id": ingress_id,
                "ingress_name": ingress.get("name"),
                "ingress_kind": ingress.get("kind"),
                "boundary_function_id": boundary_id,
                "boundary_function_name": function.get("name"),
                "address": function.get("address"),
                "parser_surface_id": parser_surface.get("id"),
                "parser_surface_name": parser_surface.get("name"),
                "path": {
                    "id": _path_id(ingress_id, *path, parser_surface.get("id")),
                    "function_ids": path,
                    "function_names": path_names,
                    "depth": max(0, len(path) - 1),
                },
                "runtime_parser_flows": [runtime_flow],
                "score": int(ingress.get("score") or 0) + 95 - (max(0, len(path) - 1) * 8),
                "confidence": "confirmed",
                "evidence_tier": EvidenceTier.OBSERVED_RUNTIME.value,
                "evidence_ids": list(dict.fromkeys(evidence_ids)),
                "claim": "parser_boundary_candidate_only",
                "evidence_note": (
                    "Frida parser callsite backtrace contained the recovered ingress and parser caller; "
                    "this proves execution shape, not attacker-byte taint or a callable ABI."
                ),
            })

        queue: deque[tuple[str, list[str]]] = deque([(start_id, [start_id])])
        visited: set[str] = {start_id}
        while queue:
            function_id, path = queue.popleft()
            depth = len(path) - 1
            for parser_edge in parser_calls.get(function_id, []):
                key = (ingress_id, function_id)
                if key in seen:
                    continue
                seen.add(key)
                runtime_flows = runtime_parser_by_function.get(function_id, [])
                tier = EvidenceTier.OBSERVED_RUNTIME if runtime_flows else EvidenceTier.XREF_BACKED
                confidence = "confirmed" if runtime_flows else "candidate"
                function = functions.get(function_id)
                parser_surface = surfaces.get(str(parser_edge.get("target_surface") or ""))
                if function is None or parser_surface is None:
                    continue
                path_names = [str(functions[item].get("name") or item) for item in path]
                record = make_evidence(
                    binary_sha256,
                    kind="parser_boundary_candidate",
                    source="frida_parser_callsite" if runtime_flows else "radare2_call_graph",
                    summary=(
                        f"Recovered parser boundary candidate {function.get('name')!r} "
                        f"behind ingress {ingress.get('name')!r}"
                    ),
                    tier=tier,
                    confidence=confidence,
                    reproducible=not bool(runtime_flows),
                    tool="frida" if runtime_flows else "radare2",
                    location=f"{binary_path}@{function.get('address') or ''}",
                    data={
                        "ingress_id": ingress_id,
                        "boundary_function_id": function_id,
                        "parser_surface_id": parser_surface.get("id"),
                        "path_function_ids": path,
                        "path_function_names": path_names,
                        "depth": depth,
                        "runtime_parser_flows": [item.get("id") for item in runtime_flows],
                    },
                )
                records.append(record)
                evidence_ids = [
                    *list(ingress.get("evidence_ids") or []),
                    record.id,
                    *[
                        evidence_id
                        for flow in runtime_flows
                        for evidence_id in (flow.get("evidence_ids") or [])
                    ],
                ]
                candidates.append({
                    "id": _id(ingress_id, function_id, parser_surface.get("id")),
                    "ingress_id": ingress_id,
                    "ingress_name": ingress.get("name"),
                    "ingress_kind": ingress.get("kind"),
                    "boundary_function_id": function_id,
                    "boundary_function_name": function.get("name"),
                    "address": function.get("address"),
                    "parser_surface_id": parser_surface.get("id"),
                    "parser_surface_name": parser_surface.get("name"),
                    "path": {
                        "id": _path_id(ingress_id, *path, parser_surface.get("id")),
                        "function_ids": path,
                        "function_names": path_names,
                        "depth": depth,
                    },
                    "runtime_parser_flows": runtime_flows,
                    "score": int(ingress.get("score") or 0) + 60 - (depth * 8) + (35 if runtime_flows else 0),
                    "confidence": confidence,
                    "evidence_tier": tier.value,
                    "evidence_ids": list(dict.fromkeys(evidence_ids)),
                    "claim": "parser_boundary_candidate_only",
                    "evidence_note": (
                        "Runtime observed this function calling a parser surface; the ingress-to-boundary "
                        "path remains xref-backed and does not prove attacker-byte taint."
                        if runtime_flows else
                        "Bounded radare2 call-graph path from ingress to a function that directly calls a "
                        "parser surface; this is not proof attacker bytes traverse the path."
                    ),
                })
            if depth >= max_depth:
                continue
            for edge in internal_edges.get(function_id, []):
                target_id = str(edge.get("target_function") or "")
                if not target_id or target_id not in functions or target_id in visited:
                    continue
                visited.add(target_id)
                queue.append((target_id, [*path, target_id]))

    return sorted(
        candidates,
        key=lambda item: (-int(item.get("score") or 0), str(item.get("boundary_function_name") or "")),
    ), records


__all__ = ["extract_parser_boundaries"]
