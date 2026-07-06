"""Deterministic investigation layer for black-box binary maps.

The map substrate is deliberately mechanical. This module is the next layer up:
it reads the map, asks the graph the obvious follow-up questions, ranks the
evidence-backed leads, and writes a compact operator report.

It does not turn a likely lead into a finding. Facts, structural inferences and
hypotheses are kept separate so the report remains useful without becoming
wishful thinking.
"""

from __future__ import annotations

import shlex
from collections import defaultdict
from pathlib import Path
from typing import Any

from core.json import save_json

from .graph_store import BinaryGraphStore, graph_summary, query_edges
from .topology import discover_sibling_artifacts

_SURFACE_WEIGHTS = {
    "process_execution": 100,
    "security_boundary": 85,
    "parser": 70,
    "format_string": 65,
    "filesystem_race": 65,
    "filesystem_or_url": 60,
    "filesystem_path": 60,
    "memory_write": 55,
    "logging": 15,
}

_CLASS_TOKENS = {
    "helper": 30,
    "xpc": 30,
    "authorization": 30,
    "auth": 20,
    "jwt": 25,
    "token": 20,
    "zip": 20,
    "archive": 20,
    "command": 25,
    "process": 20,
    "network": 20,
    "url": 15,
}


def _q(value: str) -> str:
    return shlex.quote(str(value))


def _fact(
    items: list[dict[str, Any]],
    statement: str,
    *,
    tier: str,
    source: str,
    evidence_ids: list[str] | None = None,
    confidence: str = "confirmed",
) -> None:
    items.append({
        "id": f"FACT-{len(items) + 1:03d}",
        "statement": statement,
        "evidence_tier": tier,
        "confidence": confidence,
        "source": source,
        "evidence_ids": list(evidence_ids or []),
    })


def _graph_rollup(graph_path: Path) -> dict[str, Any]:
    call_edges = query_edges(graph_path, kind="CALLS")
    surface_call_edges = query_edges(graph_path, kind="CALLS_SURFACE")
    may_reach_edges = query_edges(graph_path, kind="MAY_REACH")
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in [*call_edges, *surface_call_edges, *may_reach_edges]:
        props = edge.get("props") or {}
        target_id = str(props.get("sink") or props.get("target_surface") or edge["target"]["id"])
        by_target[target_id].append(edge)
    return {
        "summary": graph_summary(graph_path),
        "queries": [
            {
                "kind": "CALLS",
                "edge_count": len(call_edges),
                "description": "Direct xref-backed calls into sink candidates.",
            },
            {
                "kind": "CALLS_SURFACE",
                "edge_count": len(surface_call_edges),
                "description": "Direct xref-backed calls into non-sink parser/security surfaces.",
            },
            {
                "kind": "MAY_REACH",
                "edge_count": len(may_reach_edges),
                "description": "Transitive xref-backed reachability into sink candidates.",
            },
        ],
        "edges_by_target": by_target,
    }


def _rank_surfaces(context: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for surface in context.get("surface_details", []):
        if not isinstance(surface, dict):
            continue
        surface_id = str(surface.get("id") or "")
        edges = graph["edges_by_target"].get(surface_id, [])
        direct_edges = [edge for edge in edges if edge.get("kind") in {"CALLS", "CALLS_SURFACE"}]
        transitive_edges = [edge for edge in edges if edge.get("kind") == "MAY_REACH"]
        score = _SURFACE_WEIGHTS.get(str(surface.get("category") or ""), 20)
        score += min(25, len(direct_edges) * 2)
        score += min(10, len(transitive_edges))
        if surface.get("is_sink"):
            score += 5
        ranked.append({
            "id": surface_id,
            "name": surface.get("name"),
            "category": surface.get("category"),
            "role": surface.get("role"),
            "is_sink": bool(surface.get("is_sink")),
            "score": score,
            "evidence_tier": surface.get("evidence_tier"),
            "presence_confidence": surface.get("presence_confidence"),
            "rationale": surface.get("evidence_note"),
            "direct_callers": len(direct_edges),
            "transitive_callers": len(transitive_edges),
            "top_callers": [
                {
                    "name": edge["source"]["name"],
                    "relationship": edge["kind"].lower(),
                    "confidence": edge.get("confidence"),
                }
                for edge in edges[:5]
            ],
            "claim": "security_surface_candidate_only",
        })
    return sorted(ranked, key=lambda item: (-item["score"], str(item["name"])))


def _rank_classes(context: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    call_edges = [
        edge
        for edges in graph["edges_by_target"].values()
        for edge in edges
        if edge.get("kind") == "CALLS"
    ]
    edges_by_function = defaultdict(list)
    for edge in call_edges:
        props = edge.get("props") or {}
        source_function = str(props.get("source_function") or "")
        if source_function:
            edges_by_function[source_function].append(edge)

    ranked: list[dict[str, Any]] = []
    classes = (context.get("class_inventory") or {}).get("classes") or []
    for item in classes:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        lowered = name.lower()
        token_hits = [token for token in _CLASS_TOKENS if token in lowered]
        methods = item.get("methods") or []
        bound_ids = {
            str(method.get("bound_function_id") or "")
            for method in methods
            if isinstance(method, dict) and method.get("bound_function_id")
        }
        class_edges = [
            edge
            for function_id in bound_ids
            for edge in edges_by_function.get(function_id, [])
        ]
        categories = sorted({
            str((edge.get("props") or {}).get("sink_category") or "")
            for edge in class_edges
            if (edge.get("props") or {}).get("sink_category")
        })
        score = min(40, len(methods))
        score += sum(_CLASS_TOKENS[token] for token in token_hits)
        score += min(30, len(class_edges) * 5)
        if score < 20:
            continue
        ranked.append({
            "id": item.get("id"),
            "name": name,
            "language": item.get("language"),
            "method_count": len(methods),
            "bound_method_count": sum(1 for method in methods if method.get("bound_function_id")),
            "keyword_hits": token_hits,
            "sink_call_edges": len(class_edges),
            "sink_categories": categories,
            "score": score,
            "evidence_tier": item.get("evidence_tier"),
            "claim": "structural_lead_only",
        })
    return sorted(ranked, key=lambda item: (-item["score"], item["name"]))


def _rank_ingress(context: dict[str, Any]) -> list[dict[str, Any]]:
    flows_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for flow in context.get("candidate_flows", []):
        if isinstance(flow, dict) and flow.get("source_function"):
            flows_by_function[str(flow["source_function"])].append(flow)
    ranked: list[dict[str, Any]] = []
    for item in context.get("external_ingress_candidates", []):
        if not isinstance(item, dict):
            continue
        bound_function_id = str(item.get("bound_function_id") or "")
        linked_flows = flows_by_function.get(bound_function_id, [])
        score = int(item.get("score") or 0)
        score += min(30, len(linked_flows) * 10)
        ranked.append({
            **item,
            "score": score,
            "linked_candidate_flows": len(linked_flows),
            "linked_sinks": sorted({str(flow.get("sink") or "") for flow in linked_flows if flow.get("sink")}),
        })
    return sorted(ranked, key=lambda item: (-item["score"], str(item.get("name") or "")))


def _rank_parser_boundaries(context: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        [
            item for item in context.get("parser_boundary_candidates", [])
            if isinstance(item, dict)
        ],
        key=lambda item: (-int(item.get("score") or 0), str(item.get("boundary_function_name") or "")),
    )


def _build_actions(
    *,
    target_path: str,
    run_dir: Path,
    context: dict[str, Any],
    manifest: Any,
    artifacts: list[dict[str, Any]],
    ranked_surfaces: list[dict[str, Any]],
    ranked_ingress: list[dict[str, Any]],
    ranked_parser_boundaries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    scope = context.get("analysis_scope") or {}
    metadata_only = scope.get("analysis_depth") == "metadata_only"

    def add(priority: int, kind: str, command: str, why: str, evidence_needed: str) -> None:
        actions.append({
            "priority": priority,
            "kind": kind,
            "command": command,
            "why": why,
            "evidence_needed": evidence_needed,
        })

    for artifact in artifacts:
        if artifact["kind"] == "privileged_helper" and artifact["present"]:
            add(
                100,
                "map_sibling",
                f"/binary investigate {_q(artifact['path'])}",
                f"Map declared privileged helper {artifact['name']} separately.",
                "A separate byte-bound map of the helper side of the trust boundary.",
            )
    if metadata_only:
        add(
            110,
            "deep_map",
            f"/binary investigate {_q(target_path)}",
            "This run was metadata-only, so RAPTOR has not built the function/xref graph yet.",
            "A full static map before runtime or fuzz follow-on work is treated as meaningful evidence.",
        )
    if int(scope.get("slice_count") or 0) > 1 and not scope.get("all_slices_analysed"):
        selected = str(scope.get("selected_arch") or "")
        for slice_info in context.get("binary_slices", []):
            arch = str(slice_info.get("arch") or "")
            if arch and arch != selected:
                add(
                    90,
                    "map_slice",
                    f"/binary investigate {_q(target_path)} --slice-arch {_q(arch)}",
                    f"Deeply map the unanalysed {arch} Mach-O slice.",
                    "A second architecture map rather than assuming the selected slice represents both builds.",
                )
                break
    fuzz_suitability = context.get("fuzz_suitability") or {}
    if (
        not metadata_only
        and not context.get("runtime_input_flows")
        and fuzz_suitability.get("runtime_strategy", "direct_process") == "direct_process"
    ):
        ingress_hint = ""
        if ranked_ingress:
            ingress_hint = f" Start with {ranked_ingress[0]['name']}."
        add(
            80,
            "trace_parser",
            f"/binary trace-parser {_q(str(run_dir))} --duration 30",
            f"Observe which recovered functions actually call input and parser APIs.{ingress_hint}",
            "Observed runtime callsites and parser backtraces bound back to recovered functions.",
        )
    elif (
        not metadata_only
        and not context.get("runtime_input_flows")
        and fuzz_suitability.get("runtime_strategy") in {"kernel_harness_required", "caller_harness_required"}
    ):
        add(
            80,
            "runtime_harness",
            f"/binary report {_q(str(run_dir))}",
            str(fuzz_suitability.get("runtime_reason") or "A harness is needed before runtime tracing."),
            "A concrete host, harness or kernel trace boundary before runtime evidence is collected.",
        )
    if (
        not metadata_only
        and fuzz_suitability.get("should_run_fuzz_plan")
        and not context.get("fuzz_witnesses")
    ):
        add(
            70,
            "fuzz_plan",
            f"/binary fuzz {_q(target_path)} --plan-only",
            str(fuzz_suitability.get("reason") or "Check whether this artefact is actually a sensible fuzz target."),
            "A fuzzer capability plan and a known input mode or harness before any campaign runs.",
        )
    elif not metadata_only and fuzz_suitability.get("strategy") in {
        "extract_harness_from_ingress",
        "extract_export_harness",
        "snapshot_or_ioctl_harness",
    }:
        ingress_arg = ""
        if ranked_ingress:
            ingress_arg = f" --ingress {_q(str(ranked_ingress[0]['id']))}"
        add(
            70,
            "harness_strategy",
            f"/binary harness {_q(str(run_dir))}{ingress_arg}",
            str(fuzz_suitability.get("next_step") or "Extract a narrow harness before fuzzing."),
            "A concrete harness boundary rather than a whole-process campaign.",
        )
    if not metadata_only and ranked_surfaces:
        top = ranked_surfaces[0]
        add(
            60,
            "graph_review",
            f"/binary graph {_q(str(run_dir))} --edges --kind CALLS --json",
            f"Review xref-backed callers for the highest-ranked surface: {top['name']}.",
            "A concrete caller worth tracing or instrumenting next.",
        )
    if not metadata_only and ranked_parser_boundaries:
        top = ranked_parser_boundaries[0]
        add(
            85,
            "parser_boundary_review",
            f"/binary graph {_q(str(run_dir))} --edges --kind PARSER_BOUNDARY_FOR_INGRESS --json",
            (
                f"Review recovered parser boundary {top['boundary_function_name']} behind "
                f"{top['ingress_name']} before writing a harness."
            ),
            "A confirmed ABI/object contract or runtime parser callsite before harness source is emitted.",
        )
    return sorted(actions, key=lambda item: (-item["priority"], item["kind"]))


def build_investigation(
    result: Any,
    out_dir: Path,
    *,
    active_phases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the deterministic investigation view for one binary map result."""
    out_dir = Path(out_dir).resolve()
    context = result.context_map
    manifest = result.manifest
    graph = _graph_rollup(result.graph_path)
    artifacts = discover_sibling_artifacts(manifest)
    ranked_surfaces = _rank_surfaces(context, graph)
    ranked_classes = _rank_classes(context, graph)
    ranked_ingress = _rank_ingress(context)
    ranked_parser_boundaries = _rank_parser_boundaries(context)
    facts: list[dict[str, Any]] = []
    inferences: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []

    _fact(
        facts,
        f"Mapped {manifest.binary_format} {manifest.arch} binary {Path(manifest.binary_path).name} with SHA-256 {manifest.binary_sha256}.",
        tier="header_backed",
        source="binary-manifest.json",
        evidence_ids=[record.id for record in manifest.evidence if record.kind == "binary_intake"],
    )
    scope = context.get("analysis_scope") or {}
    metadata_only = scope.get("analysis_depth") == "metadata_only"
    if metadata_only:
        _fact(
            facts,
            f"Metadata intake recovered {len(result.input_channels)} input channel candidate(s) and {len(context.get('sink_details', []))} sink candidate(s); no function/xref map was built.",
            tier="header_backed",
            source="context-map.json",
        )
        _fact(
            facts,
            f"Metadata-only intake ran for {scope.get('selected_arch') or manifest.arch}; {scope.get('slice_count', 0)} Mach-O slice(s) were inventoried. No deep function/xref analysis was attempted.",
            tier="header_backed",
            source="binary-manifest.json",
        )
    elif scope:
        _fact(
            facts,
            f"Recovered {len(context.get('entry_points', []))} entry point candidate(s), {len(result.input_channels)} input channel candidate(s), {len(context.get('sink_details', []))} sink candidate(s), and {len(context.get('candidate_flows', []))} xref-backed candidate flow(s).",
            tier="xref_backed",
            source="context-map.json",
        )
        _fact(
            facts,
            f"Deep analysis ran for {scope.get('deep_analysis_arch') or 'no architecture'}; {scope.get('slice_count', 0)} Mach-O slice(s) were inventoried.",
            tier="header_backed",
            source="binary-manifest.json",
        )
    else:
        _fact(
            facts,
            f"Recovered {len(context.get('entry_points', []))} entry point candidate(s), {len(result.input_channels)} input channel candidate(s), {len(context.get('sink_details', []))} sink candidate(s), and {len(context.get('candidate_flows', []))} xref-backed candidate flow(s).",
            tier="xref_backed",
            source="context-map.json",
        )
    class_summary = (context.get("class_inventory") or {}).get("summary") or {}
    if class_summary.get("class_count"):
        _fact(
            facts,
            f"Recovered {class_summary.get('class_count')} Objective-C / Swift class record(s) with {class_summary.get('method_count')} method record(s).",
            tier="header_backed",
            source="context-map.json",
        )
    bundle = getattr(manifest, "app_bundle", None)
    if bundle:
        _fact(
            facts,
            f"App bundle metadata declares identifier {bundle.identifier or 'unknown'}, {len(bundle.privileged_executables)} privileged executable(s), {len(bundle.xpc_services)} XPC service(s), and {len(bundle.ats_exception_domains)} ATS exception domain(s).",
            tier="header_backed",
            source="Info.plist",
        )
    if context.get("runtime_input_flows"):
        _fact(
            facts,
            f"Runtime evidence bound {len(context['runtime_input_flows'])} input callsite(s) back to recovered functions.",
            tier="observed_runtime",
            source="context-map.json",
        )
    if context.get("parser_boundary_candidates"):
        _fact(
            facts,
            f"Recovered {len(context['parser_boundary_candidates'])} bounded parser boundary candidate(s) behind external ingress.",
            tier="xref_backed",
            source="context-map.json",
        )
    if context.get("fuzz_witnesses"):
        _fact(
            facts,
            f"Fuzz evidence contains {len(context['fuzz_witnesses'])} crash witness(es).",
            tier="observed_runtime",
            source="context-map.json",
        )

    if ranked_surfaces:
        top = ranked_surfaces[0]
        if metadata_only:
            statement = (
                f"{top['name']} is the highest-ranked intake lead because it is a "
                f"{top['category']} {top['role']} present in the binary metadata."
            )
            not_a_claim = "This run has no xref graph yet, so it does not prove any caller or reachability."
        else:
            statement = (
                f"{top['name']} is the highest-ranked review lead because it is a "
                f"{top['category']} {top['role']} with {top['direct_callers']} direct xref-backed caller(s)."
            )
            not_a_claim = "This does not prove attacker control or exploitability."
        inferences.append({
            "id": f"INF-{len(inferences) + 1:03d}",
            "statement": statement,
            "basis": ["surface classification", "binary graph CALLS query"],
            "confidence": "candidate",
            "not_a_claim": not_a_claim,
        })
    if artifacts:
        declared = [item for item in artifacts if item["kind"] in {"privileged_helper", "xpc_service"}]
        if declared:
            inferences.append({
                "id": f"INF-{len(inferences) + 1:03d}",
                "statement": "The app bundle has separately declared executable components that should be mapped as their own trust-boundary side.",
                "basis": ["Info.plist bundle metadata", "bundle filesystem resolution"],
                "confidence": "candidate",
                "not_a_claim": "This does not prove that the main binary can reach or misuse the sibling component.",
            })
    if ranked_classes:
        lead = ranked_classes[0]
        inferences.append({
            "id": f"INF-{len(inferences) + 1:03d}",
            "statement": f"{lead['name']} is a structural review lead: {lead['method_count']} recovered method(s), keyword hits {lead['keyword_hits'] or 'none'}, and {lead['sink_call_edges']} sink call edge(s) from bound methods.",
            "basis": ["class metadata inventory", "method-to-function bindings", "binary graph CALLS query"],
            "confidence": "candidate",
            "not_a_claim": "Class names and method bindings are structure, not a vulnerability verdict.",
        })
    if ranked_parser_boundaries:
        lead = ranked_parser_boundaries[0]
        inferences.append({
            "id": f"INF-{len(inferences) + 1:03d}",
            "statement": (
                f"{lead['boundary_function_name']} is the strongest parser-boundary lead behind "
                f"{lead['ingress_name']}; it reaches {lead['parser_surface_name']} across a "
                f"bounded call-graph path of depth {lead['path']['depth']}."
            ),
            "basis": ["external ingress binding", "radare2 bounded call graph", "parser surface classification"],
            "confidence": lead.get("confidence") or "candidate",
            "not_a_claim": "This narrows the harness target; it does not prove attacker bytes traverse the path.",
        })

    if any(item["category"] == "process_execution" for item in ranked_surfaces):
        hypotheses.append({
            "id": f"HYP-{len(hypotheses) + 1:03d}",
            "title": "Input data may reach process execution primitives",
            "basis": "A process-execution sink candidate exists and has xref-backed callers.",
            "missing_evidence": [
                "runtime input callsite bound to one of the caller functions",
                "root-cause binding showing attacker-controlled command or arguments",
            ],
            "status": "unproven",
        })
    if any(item["category"] == "parser" for item in ranked_surfaces):
        hypotheses.append({
            "id": f"HYP-{len(hypotheses) + 1:03d}",
            "title": "Parser surfaces may merit targeted fuzzing",
            "basis": "Parser-related imports or metadata-backed surfaces are present.",
            "missing_evidence": [
                "known input format or harness",
                "execution-backed crash or clean coverage result",
            ],
            "status": "unproven",
        })
    if bundle and bundle.ats_exception_domains:
        hypotheses.append({
            "id": f"HYP-{len(hypotheses) + 1:03d}",
            "title": "ATS exception domains warrant transport review",
            "basis": f"Info.plist declares ATS exception domain(s): {', '.join(bundle.ats_exception_domains)}.",
            "missing_evidence": [
                "runtime network observation or configuration proof",
                "evidence that sensitive data actually crosses an insecure transport",
            ],
            "status": "unproven",
        })
    if any(item["kind"] == "privileged_helper" for item in artifacts):
        hypotheses.append({
            "id": f"HYP-{len(hypotheses) + 1:03d}",
            "title": "Privileged helper boundary needs a separate binary map",
            "basis": "The app declares a privileged executable in bundle metadata.",
            "missing_evidence": [
                "byte-bound map of the helper binary",
                "runtime or protocol evidence for the main-to-helper interaction",
            ],
            "status": "unproven",
        })

    actions = _build_actions(
        target_path=manifest.binary_path,
        run_dir=out_dir,
        context=context,
        manifest=manifest,
        artifacts=artifacts,
        ranked_surfaces=ranked_surfaces,
        ranked_ingress=ranked_ingress,
        ranked_parser_boundaries=ranked_parser_boundaries,
    )
    handoff = result.validation_handoff or {}
    return {
        "schema_version": 1,
        "target_path": manifest.binary_path,
        "binary_sha256": manifest.binary_sha256,
        "status": "metadata_only" if metadata_only else handoff.get("status", "static_only"),
        "can_promote_findings": bool(handoff.get("can_promote_findings", False)),
        "summary": {
            "entry_point_candidates": len(context.get("entry_points", [])),
            "input_channel_candidates": len(result.input_channels),
            "sink_candidates": len(context.get("sink_details", [])),
            "surface_candidates": len(context.get("surface_details", [])),
            "candidate_flows": len(context.get("candidate_flows", [])),
            "runtime_input_flows": len(context.get("runtime_input_flows", [])),
            "fuzz_witnesses": len(context.get("fuzz_witnesses", [])),
            "ranked_surfaces": len(ranked_surfaces),
            "ranked_classes": len(ranked_classes),
            "ranked_ingress": len(ranked_ingress),
            "parser_boundary_candidates": len(ranked_parser_boundaries),
            "discovered_artifacts": len(artifacts),
        },
        "facts": facts,
        "structural_inferences": inferences,
        "hypotheses": hypotheses,
        "ranked_surfaces": ranked_surfaces[:10],
        "ranked_classes": ranked_classes[:10],
        "ranked_ingress": ranked_ingress[:10],
        "ranked_parser_boundaries": ranked_parser_boundaries[:10],
        "discovered_artifacts": artifacts,
        "component_topology": context.get("component_topology") or {},
        "fuzz_suitability": context.get("fuzz_suitability") or {},
        "automatic_graph_queries": graph["queries"],
        "active_phases": list(active_phases or []),
        "priority_queue": actions,
        "non_claims": [
            "A surface ranking is not a finding.",
            "A class name or selector is not proof of reachability.",
            "An xref-backed caller is not taint proof.",
            "A sibling or helper declaration is not proof of a broken trust boundary.",
        ],
    }


def _md_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_investigation_report(investigation: dict[str, Any]) -> str:
    summary = investigation["summary"]
    lines = [
        "# RAPTOR Binary Investigation",
        "",
        f"Target: `{investigation['target_path']}`",
        f"SHA-256: `{investigation['binary_sha256']}`",
        f"Status: `{investigation['status']}`",
        "",
        "## One-screen Summary",
        "",
        (
            f"- {summary['entry_point_candidates']} entry point candidate(s), "
            f"{summary['input_channel_candidates']} input channel candidate(s), "
            f"{summary['sink_candidates']} sink candidate(s), "
            f"{summary['candidate_flows']} xref-backed candidate flow(s)."
        ),
        (
            f"- {summary['runtime_input_flows']} runtime input flow(s), "
            f"{summary['fuzz_witnesses']} fuzz witness(es), "
            f"{summary['discovered_artifacts']} sibling/helper artefact(s) discovered."
        ),
        f"- {summary['ranked_ingress']} external ingress candidate(s) ranked.",
        f"- {summary['parser_boundary_candidates']} parser boundary candidate(s) recovered.",
        f"- Findings promotable from current evidence: {'yes' if investigation['can_promote_findings'] else 'no'}.",
        "",
        "## Highest-value External Ingress",
        "",
        "| Rank | Ingress | Kind | Boundary | Linked flows | Why it matters |",
        "|---|---|---|---|---:|---|",
    ]
    for index, item in enumerate(investigation["ranked_ingress"][:5], start=1):
        lines.append(
            f"| {index} | `{_md_escape(item['name'])}` | `{_md_escape(item['kind'])}` | "
            f"`{_md_escape(item['boundary'])}` | {item['linked_candidate_flows']} | "
            f"`{_md_escape(item['external_control'])}` |"
        )
    if not investigation["ranked_ingress"]:
        lines.append("| - | none | - | - | 0 | No external ingress recovered. |")

    lines.extend([
        "",
        "## Recovered Parser Boundaries",
        "",
        "| Rank | Boundary function | Ingress | Parser surface | Depth | Tier |",
        "|---|---|---|---|---:|---|",
    ])
    for index, item in enumerate(investigation["ranked_parser_boundaries"][:5], start=1):
        lines.append(
            f"| {index} | `{_md_escape(item['boundary_function_name'])}` | "
            f"`{_md_escape(item['ingress_name'])}` | `{_md_escape(item['parser_surface_name'])}` | "
            f"{item['path']['depth']} | `{_md_escape(item['evidence_tier'])}` |"
        )
    if not investigation["ranked_parser_boundaries"]:
        lines.append("| - | none | - | - | 0 | No bounded ingress-to-parser path recovered. |")

    lines.extend([
        "",
        "## Highest-value Leads",
        "",
        "| Rank | Surface | Category | Direct callers | Why it is here |",
        "|---|---|---|---:|---|",
    ])
    for index, item in enumerate(investigation["ranked_surfaces"][:5], start=1):
        lines.append(
            f"| {index} | `{_md_escape(item['name'])}` | `{_md_escape(item['category'])}` | "
            f"{item['direct_callers']} | {_md_escape(item['rationale'])} |"
        )
    if not investigation["ranked_surfaces"]:
        lines.append("| - | none | - | 0 | No ranked surfaces recovered. |")

    lines.extend(["", "## Facts", ""])
    lines.extend(
        f"- [{item['evidence_tier']}] {item['statement']}"
        for item in investigation["facts"]
    )
    lines.extend(["", "## Structural Inferences (Not Findings)", ""])
    if investigation["structural_inferences"]:
        for item in investigation["structural_inferences"]:
            lines.append(f"- {item['statement']} {item['not_a_claim']}")
    else:
        lines.append("- No structural inferences were strong enough to surface.")

    if investigation["ranked_classes"]:
        lines.extend([
            "",
            "## Structural Class Leads",
            "",
            "| Rank | Class | Methods | Keyword hits | Sink call edges |",
            "|---|---|---:|---|---:|",
        ])
        for index, item in enumerate(investigation["ranked_classes"][:5], start=1):
            lines.append(
                f"| {index} | `{_md_escape(item['name'])}` | {item['method_count']} | "
                f"`{_md_escape(', '.join(item['keyword_hits']) or 'none')}` | "
                f"{item['sink_call_edges']} |"
            )

    if investigation["discovered_artifacts"]:
        lines.extend([
            "",
            "## Discovered Sibling Artefacts",
            "",
            "| Kind | Name | Path | Why it is here |",
            "|---|---|---|---|",
        ])
        for item in investigation["discovered_artifacts"]:
            path = item["path"] or "not resolved on disk"
            lines.append(
                f"| `{_md_escape(item['kind'])}` | `{_md_escape(item['name'])}` | "
                f"`{_md_escape(path)}` | `{_md_escape(item['declared_by'])}` |"
            )

    lines.extend(["", "## Automatic Graph Queries", ""])
    for item in investigation["automatic_graph_queries"]:
        lines.append(f"- `{item['kind']}`: {item['edge_count']} edge(s). {item['description']}")

    lines.extend(["", "## Hypotheses Requiring Evidence", ""])
    if investigation["hypotheses"]:
        for item in investigation["hypotheses"]:
            missing = "; ".join(item["missing_evidence"])
            lines.append(f"- `{item['id']}` {item['title']}. Missing: {missing}.")
    else:
        lines.append("- No hypotheses generated from the current evidence.")

    if investigation.get("active_phases"):
        lines.extend(["", "## Active Phases", ""])
        for item in investigation["active_phases"]:
            reason = f" Reason: {item['reason']}" if item.get("reason") else ""
            lines.append(
                f"- `{item['kind']}`: `{item['status']}`"
                f" ({item.get('output_dir') or 'no output directory'}).{reason}"
            )

    suitability = investigation.get("fuzz_suitability") or {}
    if suitability:
        lines.extend([
            "",
            "## Fuzz Strategy",
            "",
            f"- Strategy: `{suitability.get('strategy')}`",
            f"- Direct whole-target campaign recommended: {'yes' if suitability.get('direct_campaign_recommended') else 'no'}",
            f"- Runtime collection: `{suitability.get('runtime_strategy', 'direct_process')}`",
            f"- Runtime reason: {suitability.get('runtime_reason')}",
            f"- Reason: {suitability.get('reason')}",
            f"- Next step: {suitability.get('next_step')}",
        ])
        candidates = suitability.get("harness_candidates") or []
        if candidates:
            lines.extend([
                "",
                "| Candidate ingress | Kind | Why |",
                "|---|---|---|",
            ])
            for item in candidates[:5]:
                lines.append(
                    f"| `{_md_escape(item.get('name'))}` | `{_md_escape(item.get('kind'))}` | "
                    f"{_md_escape(item.get('why'))} |"
                )

    lines.extend(["", "## Priority Queue", ""])
    if investigation["priority_queue"]:
        lines.extend([
            "| Priority | Action | Command | Why |",
            "|---:|---|---|---|",
        ])
        for item in investigation["priority_queue"]:
            lines.append(
                f"| {item['priority']} | `{item['kind']}` | `{_md_escape(item['command'])}` | "
                f"{_md_escape(item['why'])} |"
            )
    else:
        lines.append("- No follow-on actions queued.")

    lines.extend(["", "## What RAPTOR Is Not Claiming", ""])
    lines.extend(f"- {item}" for item in investigation["non_claims"])
    return "\n".join(lines) + "\n"


def write_investigation(
    result: Any,
    out_dir: Path,
    *,
    active_phases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    investigation = build_investigation(result, out_dir, active_phases=active_phases)
    out_dir = Path(out_dir).resolve()
    save_json(out_dir / "binary-investigation.json", investigation)
    report_path = out_dir / "binary-investigation-report.md"
    report_path.write_text(
        render_investigation_report(investigation),
        encoding="utf-8",
    )
    store = BinaryGraphStore(result.graph_path)
    snapshot_id = store.latest_snapshot_id()
    if snapshot_id:
        store.add_artifact(snapshot_id, "binary_investigation", out_dir / "binary-investigation.json")
        store.add_artifact(snapshot_id, "binary_investigation_report", report_path)
    store.close()
    return investigation


__all__ = ["build_investigation", "render_investigation_report", "write_investigation"]
