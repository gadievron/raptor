"""Direct unit tests for parser_boundary.extract_parser_boundaries."""

from __future__ import annotations

from packages.binary_analysis.parser_boundary import extract_parser_boundaries

SHA = "b" * 64
PATH = "/bin/test"


def _make_context_map(
    functions=None, surfaces=None, edges=None,
    ingress=None, runtime_parser_flows=None,
):
    return {
        "interesting_functions": functions or [],
        "surface_details": surfaces or [],
        "call_graph_edges": edges or [],
        "external_ingress_candidates": ingress or [],
        "runtime_parser_flows": runtime_parser_flows or [],
    }


def test_no_parser_surfaces_returns_empty():
    ctx = _make_context_map(
        surfaces=[{"id": "S1", "category": "memory_write"}],
    )
    candidates, evidence = extract_parser_boundaries(
        binary_sha256=SHA, binary_path=PATH, context_map=ctx,
    )
    assert candidates == []
    assert evidence == []


def test_xref_backed_boundary_from_ingress_to_parser():
    ctx = _make_context_map(
        functions=[
            {"id": "F1", "name": "url_handler", "address": "0x1000"},
            {"id": "F2", "name": "parse_json", "address": "0x2000"},
        ],
        surfaces=[
            {"id": "S1", "name": "JSONDecoder", "category": "parser"},
        ],
        edges=[
            {"source_function": "F1", "target_function": "F2"},
            {"source_function": "F2", "target_surface": "S1"},
        ],
        ingress=[{
            "id": "ING-1", "name": "openURL", "kind": "url_handler",
            "bound_function_id": "F1", "evidence_ids": ["E1"], "score": 50,
        }],
    )
    candidates, evidence = extract_parser_boundaries(
        binary_sha256=SHA, binary_path=PATH, context_map=ctx,
    )
    assert len(candidates) >= 1
    c = candidates[0]
    assert c["ingress_id"] == "ING-1"
    assert c["boundary_function_id"] == "F2"
    assert c["parser_surface_id"] == "S1"
    assert c["evidence_tier"] == "xref_backed"
    assert c["confidence"] == "candidate"
    assert c["claim"] == "parser_boundary_candidate_only"
    assert len(evidence) >= 1


def test_runtime_strengthens_confidence():
    ctx = _make_context_map(
        functions=[
            {"id": "F1", "name": "handler", "address": "0x1000"},
            {"id": "F2", "name": "do_parse", "address": "0x2000"},
        ],
        surfaces=[
            {"id": "S1", "name": "inflate", "category": "parser"},
        ],
        edges=[
            {"source_function": "F1", "target_function": "F2"},
            {"source_function": "F2", "target_surface": "S1"},
        ],
        ingress=[{
            "id": "ING-1", "name": "recv_handler", "kind": "network_input",
            "bound_function_id": "F1", "evidence_ids": [], "score": 30,
        }],
        runtime_parser_flows=[{
            "id": "RPF-1", "function_id": "F2",
            "parser_surface_id": "S1", "evidence_ids": ["RE1"],
        }],
    )
    candidates, evidence = extract_parser_boundaries(
        binary_sha256=SHA, binary_path=PATH, context_map=ctx,
    )
    runtime_candidates = [c for c in candidates if c["evidence_tier"] == "observed_runtime"]
    assert len(runtime_candidates) >= 1
    assert runtime_candidates[0]["confidence"] == "confirmed"


def test_max_depth_limits_search():
    functions = [{"id": f"F{i}", "name": f"fn_{i}", "address": f"0x{i}000"} for i in range(10)]
    edges = [{"source_function": f"F{i}", "target_function": f"F{i+1}"} for i in range(9)]
    edges.append({"source_function": "F9", "target_surface": "S1"})

    ctx = _make_context_map(
        functions=functions,
        surfaces=[{"id": "S1", "name": "inflate", "category": "parser"}],
        edges=edges,
        ingress=[{
            "id": "ING-1", "name": "entry", "kind": "process_entry",
            "bound_function_id": "F0", "evidence_ids": [], "score": 10,
        }],
    )
    candidates, _ = extract_parser_boundaries(
        binary_sha256=SHA, binary_path=PATH, context_map=ctx, max_depth=3,
    )
    assert len(candidates) == 0, "Should not find a boundary beyond max_depth"

    candidates, _ = extract_parser_boundaries(
        binary_sha256=SHA, binary_path=PATH, context_map=ctx, max_depth=10,
    )
    assert len(candidates) >= 1, "Should find boundary within generous depth"


def test_runtime_backtrace_recovers_hidden_static_edge():
    ctx = _make_context_map(
        functions=[
            {"id": "F1", "name": "objc_handler", "address": "0x1000"},
            {"id": "F2", "name": "swift_parse", "address": "0x2000"},
        ],
        surfaces=[
            {"id": "S1", "name": "XMLParser", "category": "parser"},
        ],
        edges=[],
        ingress=[{
            "id": "ING-1", "name": "openURL", "kind": "url_handler",
            "bound_function_id": "F1", "evidence_ids": [], "score": 40,
        }],
        runtime_parser_flows=[{
            "id": "RPF-1", "function_id": "F2",
            "parser_surface_id": "S1",
            "backtrace_function_ids": ["F1", "F2"],
            "evidence_ids": ["RE1"],
        }],
    )
    candidates, evidence = extract_parser_boundaries(
        binary_sha256=SHA, binary_path=PATH, context_map=ctx,
    )
    backtrace_candidates = [
        c for c in candidates
        if c["evidence_tier"] == "observed_runtime"
        and c["boundary_function_id"] == "F2"
    ]
    assert len(backtrace_candidates) >= 1
