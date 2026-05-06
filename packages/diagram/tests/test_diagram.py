#!/usr/bin/env python3
"""Tests for the diagram generation package."""

import json
from pathlib import Path

from ..sanitize import sanitize, sanitize_id
from ..findings_summary import generate_verdict_pie, generate_type_pie
from ..context_map import generate as gen_context_map
from ..flow_trace import generate as gen_flow_trace
from ..attack_tree import generate as gen_attack_tree
from ..attack_paths import generate as gen_attack_paths, generate_single
from ..hypotheses import generate as gen_hypotheses
from ..renderer import render_directory, render_and_write


def assert_no_mermaid_directive_injection(output: str) -> None:
    """Assert payloads did not break out into Mermaid directive lines."""
    assert "\n    click " not in output.lower()


def assert_usable_mermaid_flowchart(output: str) -> None:
    """Assert generated Mermaid remains a recognizable, renderable flowchart."""
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]
    assert lines, "Mermaid output is empty"
    assert lines[0] in {"flowchart TD", "flowchart LR"}
    assert any("-->" in line or "-." in line for line in lines), "flowchart has no edges"
    assert any("[\"" in line or "[/\"" in line or "([\"" in line for line in lines), "flowchart has no labelled nodes"
    assert "```" not in output, "raw flowchart generators should not emit markdown fences"


def extract_mermaid_blocks(markdown: str) -> list[str]:
    """Return the contents of fenced Mermaid blocks from rendered markdown."""
    blocks: list[str] = []
    in_block = False
    current: list[str] = []
    for line in markdown.splitlines():
        if line.strip() == "```mermaid":
            in_block = True
            current = []
            continue
        if in_block and line.strip() == "```":
            blocks.append("\n".join(current).strip())
            in_block = False
            continue
        if in_block:
            current.append(line)
    return blocks


# ---------------------------------------------------------------------------
# sanitize tests
# ---------------------------------------------------------------------------

class TestSanitize:
    def test_quotes_replaced(self):
        assert '"' not in sanitize('say "hello"')

    def test_angle_brackets_escaped(self):
        assert "&lt;" in sanitize("<script>")
        assert "&gt;" in sanitize("</script>")

    def test_braces_replaced(self):
        assert "{" not in sanitize("if (x) { y }")
        assert "}" not in sanitize("if (x) { y }")

    def test_newlines_removed(self):
        assert "\n" not in sanitize("line1\nline2")

    def test_non_string_input(self):
        assert sanitize(42) == "42"
        assert sanitize(None) == "None"

    def test_truncation(self):
        long = "a" * 100
        result = sanitize(long, max_len=20)
        assert len(result) == 20
        assert result.endswith("...")

    def test_no_truncation_by_default(self):
        long = "a" * 200
        assert len(sanitize(long)) == 200

    def test_ampersand_escaped_before_angle_brackets(self):
        result = sanitize("Tom & Jerry <script>")
        assert "&amp;" in result
        assert "&lt;script&gt;" in result

    def test_sanitize_id_removes_mermaid_callback_injection_chars(self):
        payload = "node1; click node1 javascript:alert(1)"
        result = sanitize_id(payload)
        assert ";" not in result
        assert " " not in result
        assert ":" not in result
        assert "(" not in result
        assert ")" not in result

    def test_sanitize_id_never_returns_empty(self):
        assert sanitize_id("!@#$%^*()[]{}") == "node"

    def test_sanitize_id_preserves_replacement_position(self):
        assert sanitize_id("A!") == "A_"
        assert sanitize_id("!A") == "_A"

    def test_line_separator_chars_removed(self):
        result = sanitize("safe\rclick X javascript:alert(1)\u2028more\u2029text")
        assert "\r" not in result
        assert "\u2028" not in result
        assert "\u2029" not in result


# ---------------------------------------------------------------------------
# findings_summary tests
# ---------------------------------------------------------------------------

class TestFindingsSummary:
    def test_verdict_pie(self):
        findings = [
            {"ruling": {"status": "exploitable"}},
            {"ruling": {"status": "confirmed"}},
            {"ruling": {"status": "ruled_out"}},
        ]
        out = generate_verdict_pie(findings)
        assert "pie title Finding Verdicts" in out
        assert "Exploitable" in out
        assert "Confirmed" in out
        assert "Ruled Out" in out

    def test_verdict_pie_colours(self):
        findings = [
            {"ruling": {"status": "exploitable"}},
            {"ruling": {"status": "confirmed"}},
        ]
        out = generate_verdict_pie(findings)
        assert "init" in out
        assert "#dc2626" in out  # exploitable red
        assert "#f97316" in out  # confirmed orange

    def test_type_pie(self):
        findings = [
            {"vuln_type": "buffer_overflow"},
            {"vuln_type": "buffer_overflow"},
            {"vuln_type": "xss"},
        ]
        out = generate_type_pie(findings)
        assert "pie title Vulnerability Types" in out
        assert "Buffer Overflow" in out
        assert "Cross-Site Scripting" in out

    def test_empty(self):
        out = generate_verdict_pie([])
        assert "No findings" in out

    def test_agentic_format(self):
        findings = [
            {"is_true_positive": True, "is_exploitable": True},
            {"is_true_positive": False},
        ]
        out = generate_verdict_pie(findings)
        assert "Exploitable" in out
        assert "False Positive" in out

    def test_pie_labels_are_sanitized(self):
        payload = "xss\"\n    click X javascript:alert(1)\n    X[\""
        out = generate_type_pie([{"vuln_type": payload}])
        assert_no_mermaid_directive_injection(out)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CONTEXT_MAP_MINIMAL = {
    "sources": [{"type": "http_route", "entry": "POST /api/query @ src/routes.py:10"}],
    "sinks": [{"type": "db_query", "location": "src/db.py:50"}],
    "trust_boundaries": [{"boundary": "JWT middleware", "check": "src/auth.py:12"}],
}

CONTEXT_MAP_FULL = {
    "meta": {"target": "testapp", "app_type": "web_app", "language": ["python"]},
    "entry_points": [
        {"id": "EP-001", "type": "http_route", "method": "POST", "path": "/api/query",
         "file": "src/routes.py", "line": 10, "auth_required": True},
        {"id": "EP-002", "type": "http_route", "method": "GET", "path": "/public",
         "file": "src/routes.py", "line": 30, "auth_required": False},
    ],
    "boundary_details": [
        {"id": "TB-001", "type": "auth_check", "boundary": "JWT middleware",
         "file": "src/auth.py", "line": 12, "covers": ["EP-001"], "gaps": ""},
    ],
    "sink_details": [
        {"id": "SINK-001", "type": "db_query", "operation": "cursor.execute(raw_sql)",
         "file": "src/db.py", "line": 50, "reaches_from": ["EP-001"],
         "trust_boundaries_crossed": ["TB-001"], "parameterized": False},
    ],
    "unchecked_flows": [
        {"entry_point": "EP-002", "sink": "SINK-001", "missing_boundary": "No auth on public endpoint"},
    ],
}

FLOW_TRACE_DATA = {
    "id": "TRACE-001",
    "name": "POST /api/query → db_query",
    "steps": [
        {"step": 1, "type": "entry", "definition": "src/routes.py:10",
         "description": "POST handler receives JSON body", "tainted_var": "request.json['query']",
         "transform": "none", "confidence": "high"},
        {"step": 2, "type": "call", "call_site": "src/routes.py:18",
         "definition": "src/service.py:5",
         "description": "Passes query to QueryService.run()", "tainted_var": "query_str",
         "transform": "none", "confidence": "high"},
        {"step": 3, "type": "sink", "call_site": "src/service.py:31",
         "definition": "psycopg2.cursor.execute()",
         "description": "Raw SQL via f-string", "tainted_var": "query_str",
         "transform": "none", "confidence": "high", "sink_type": "db_query",
         "parameterized": False, "injectable": True},
    ],
    "branches": [
        {"branch_point": "src/routes.py:14", "condition": "if request.json.get('admin')",
         "outcome": "Bypasses auth entirely"},
    ],
    "attacker_control": {"level": "full", "what": "Full control over query field via POST body"},
    "summary": {"flow_confirmed": True, "verdict": "Direct SQLi", "confidence": "high"},
}

ATTACK_TREE_DATA = {
    "root": "ROOT",
    "nodes": [
        {"id": "ROOT", "goal": "Extract user data", "technique": "SQL Injection",
         "status": "exploring", "leads_to": "N1, N2"},
        {"id": "N1", "goal": "Direct injection", "technique": "Unsanitized POST param",
         "status": "confirmed", "leads_to": ""},
        {"id": "N2", "goal": "Auth bypass", "technique": "Admin param shortcut",
         "status": "disproven", "leads_to": ""},
    ],
}

HYPOTHESES_DATA = [
    {
        "id": "HYPO-001",
        "finding": "FIND-001",
        "claim": "POST body reaches raw SQL execution with no parameterization",
        "status": "confirmed",
        "predictions": [
            {
                "id": "PRED-001",
                "prediction": "Input ' OR 1=1-- returns all rows",
                "result": "200 response with all user rows returned",
                "status": "confirmed",
            },
            {
                "id": "PRED-002",
                "prediction": "UNION SELECT returns data from other tables",
                "result": "query returns schema info",
                "status": "confirmed",
            },
        ],
    },
    {
        "id": "HYPO-002",
        "finding": "FIND-002",
        "claim": "Error-based injection leaks schema info",
        "status": "disproven",
        "predictions": [
            {
                "id": "PRED-003",
                "prediction": "Invalid syntax returns DB error message",
                "result": "Error messages suppressed by application",
                "status": "disproven",
            },
        ],
    },
]

ATTACK_PATHS_DATA = [
    {
        "id": "PATH-001",
        "name": "Direct SQLi via POST /api/query",
        "finding": "FIND-001",
        "steps": [
            {"step": 1, "type": "entry", "call_site": None, "definition": "src/routes.py:10",
             "description": "POST handler", "tainted_var": "request.json['query']"},
            {"step": 2, "type": "sink", "call_site": "src/service.py:31",
             "definition": "cursor.execute()", "description": "Raw SQL", "tainted_var": "query_str"},
        ],
        "proximity": 9,
        "blockers": [],
        "status": "confirmed",
    },
    {
        "id": "PATH-002",
        "name": "Admin bypass route",
        "finding": "FIND-001",
        "steps": [{"step": 1, "type": "entry", "description": "Admin shortcut"}],
        "proximity": 2,
        "blockers": [{"description": "Admin flag not user-controlled"}],
        "status": "blocked",
    },
]


# ---------------------------------------------------------------------------
# context_map tests
# ---------------------------------------------------------------------------

class TestContextMap:
    def test_minimal_input_produces_flowchart(self):
        out = gen_context_map(CONTEXT_MAP_MINIMAL)
        assert out.startswith("flowchart LR")

    def test_full_input_contains_ep_ids(self):
        out = gen_context_map(CONTEXT_MAP_FULL)
        assert "EP-001" in out
        assert "EP-002" in out

    def test_trust_boundary_nodes_present(self):
        out = gen_context_map(CONTEXT_MAP_FULL)
        assert "TB-001" in out

    def test_sink_nodes_present(self):
        out = gen_context_map(CONTEXT_MAP_FULL)
        assert "SINK-001" in out

    def test_unchecked_flow_dashed_edge(self):
        out = gen_context_map(CONTEXT_MAP_FULL)
        assert ".->" in out or "-.->" in out

    def test_public_endpoint_labelled(self):
        out = gen_context_map(CONTEXT_MAP_FULL)
        assert "PUBLIC" in out

    def test_style_classes_present(self):
        out = gen_context_map(CONTEXT_MAP_FULL)
        assert "classDef ep" in out
        assert "classDef tb" in out
        assert "classDef sink" in out

    def test_empty_data_does_not_crash(self):
        out = gen_context_map({})
        assert "flowchart LR" in out

    def test_special_chars_sanitized(self):
        data = {
            "entry_points": [
                {"id": "EP-001", "type": "http_route", "path": '/api/<id>"test>',
                 "file": "src/routes.py", "line": 1, "auth_required": True}
            ],
        }
        out = gen_context_map(data)
        # The original double-quote in the path should be replaced with single-quote
        assert '"test>' not in out
        # HTML-escaped angle brackets should be present
        assert "&lt;" in out or "&gt;" in out

    def test_sanitized_context_map_is_still_usable_mermaid(self):
        data = {
            "entry_points": [
                {"id": "EP-001; click EP-001 javascript:alert(1)", "path": "/api/<tenant>"}
            ],
            "boundary_details": [
                {"id": "TB-001; click TB-001 javascript:alert(1)", "covers": ["EP-001"]}
            ],
            "sink_details": [
                {"id": "SINK-001; click SINK-001 javascript:alert(1)", "operation": "open().write()"}
            ],
        }
        out = gen_context_map(data)
        assert_no_mermaid_directive_injection(out)
        assert_usable_mermaid_flowchart(out)

    def test_class_assignments_use_sanitized_ids(self):
        data = {
            "entry_points": [
                {"id": "EP-001; click EP-001 javascript:alert(1)", "path": "/"}
            ],
            "boundary_details": [
                {"id": "TB-001; click TB-001 javascript:alert(1)", "covers": []}
            ],
            "sink_details": [
                {"id": "SINK-001; click SINK-001 javascript:alert(1)", "operation": "sink"}
            ],
        }
        out = gen_context_map(data)
        class_lines = [line.strip() for line in out.splitlines() if line.strip().startswith("class ")]
        assert class_lines
        assert all(";" not in line for line in class_lines)
        assert all("javascript:" not in line for line in class_lines)
        assert all(" click " not in line for line in class_lines)
        assert f"class {sanitize_id(data['entry_points'][0]['id'])} ep" in out
        assert f"class {sanitize_id(data['boundary_details'][0]['id'])} tb" in out
        assert f"class {sanitize_id(data['sink_details'][0]['id'])} sink" in out


# ---------------------------------------------------------------------------
# flow_trace tests
# ---------------------------------------------------------------------------

class TestFlowTrace:
    def test_produces_flowchart_td(self):
        out = gen_flow_trace(FLOW_TRACE_DATA)
        assert out.startswith("flowchart TD")

    def test_all_steps_present(self):
        out = gen_flow_trace(FLOW_TRACE_DATA)
        assert "S1" in out
        assert "S2" in out
        assert "S3" in out

    def test_entry_and_sink_style_classes(self):
        out = gen_flow_trace(FLOW_TRACE_DATA)
        assert "classDef entry" in out
        assert "classDef sink" in out

    def test_branch_node_rendered(self):
        out = gen_flow_trace(FLOW_TRACE_DATA)
        assert "BR1" in out

    def test_attacker_control_node(self):
        out = gen_flow_trace(FLOW_TRACE_DATA)
        assert "CTRL" in out
        assert "full" in out.lower()

    def test_title_present(self):
        out = gen_flow_trace(FLOW_TRACE_DATA)
        assert "TITLE" in out

    def test_empty_steps(self):
        out = gen_flow_trace({"id": "T1", "name": "empty", "steps": []})
        assert "No steps" in out

    def test_step_chain_edges(self):
        out = gen_flow_trace(FLOW_TRACE_DATA)
        assert "S1 --> S2" in out
        assert "S2 --> S3" in out

    def test_branch_attaches_to_nearest_line_not_fallback(self):
        # Branch point is apis.py:63; step 1 is apis.py:61 (closest ≤ 63)
        # step 3 is apis.py:69 (after branch point).
        # Should attach to S1, not the last step.
        data = {
            "id": "T-BP",
            "name": "branch line test",
            "steps": [
                {"step": 1, "type": "entry", "definition": "introduction/apis.py:61",
                 "description": "entry", "tainted_var": "x", "confidence": "high"},
                {"step": 2, "type": "sink", "call_site": "introduction/apis.py:69",
                 "definition": "open().write()", "description": "write",
                 "tainted_var": "x", "confidence": "high"},
            ],
            "branches": [
                {"branch_point": "introduction/apis.py:63",
                 "condition": "if method == POST",
                 "outcome": "Only POST writes"},
            ],
            "attacker_control": {},
        }
        out = gen_flow_trace(data)
        # BR1 should be attached to S1 (line 61, closest ≤ 63), not S2 (line 69 > 63)
        assert "S1 -. \"branch\" .-> BR1" in out
        assert "S2 -. \"branch\" .-> BR1" not in out

    def test_branch_exact_match_still_works(self):
        # When the branch_point exactly matches a step location, use that step
        data = {
            "id": "T-EXACT",
            "name": "exact match test",
            "steps": [
                {"step": 1, "type": "entry", "definition": "src/routes.py:10",
                 "description": "entry", "tainted_var": "q", "confidence": "high"},
                {"step": 2, "type": "call", "call_site": "src/routes.py:14",
                 "definition": "src/service.py:5",
                 "description": "call", "tainted_var": "q", "confidence": "high"},
            ],
            "branches": [
                {"branch_point": "src/routes.py:14",
                 "condition": "if admin",
                 "outcome": "bypass"},
            ],
            "attacker_control": {},
        }
        out = gen_flow_trace(data)
        assert "S2 -. \"branch\" .-> BR1" in out


    def test_step_ids_and_class_assignments_are_sanitized(self):
        data = {
            "id": "TRACE-X",
            "name": "malicious step id",
            "steps": [
                {
                    "step": "1; click S1 javascript:alert(1)",
                    "type": "entry",
                    "definition": "src/routes.py:10",
                    "description": "entry",
                }
            ],
            "branches": [{"branch_point": "src/routes.py:10", "condition": "x", "outcome": "y"}],
        }
        out = gen_flow_trace(data)
        assert_no_mermaid_directive_injection(out)
        assert "class S1__click_S1_javascript_alert_1_ entry" in out
        assert "S1__click_S1_javascript_alert_1_ -. \"branch\" .-> BR1" in out

    def test_label_fields_do_not_escape_into_directives(self):
        payload = "X\"]\n    click X javascript:alert(1)\n    Y[\""
        data = {
            "id": "TRACE-X",
            "name": payload,
            "steps": [
                {
                    "step": 1,
                    "type": payload,
                    "definition": payload,
                    "description": payload,
                    "tainted_var": payload,
                    "confidence": payload,
                }
            ],
            "branches": [{"branch_point": payload, "condition": payload, "outcome": payload}],
            "attacker_control": {"level": payload, "what": payload},
        }
        assert_no_mermaid_directive_injection(gen_flow_trace(data))

    def test_sanitized_flow_trace_is_still_usable_mermaid(self):
        payload = "X\"]\n    click X javascript:alert(1)\n    Y[\""
        data = {
            "id": "TRACE-X",
            "name": payload,
            "steps": [
                {"step": 1, "type": "entry", "definition": "src/routes.py:10", "description": payload},
                {"step": 2, "type": "sink", "definition": "src/db.py:50", "description": "write"},
            ],
            "branches": [{"branch_point": "src/routes.py:10", "condition": payload, "outcome": payload}],
        }
        out = gen_flow_trace(data)
        assert_no_mermaid_directive_injection(out)
        assert_usable_mermaid_flowchart(out)

    def test_uppercase_step_type_preserves_escaped_entities(self):
        out = gen_flow_trace({
            "id": "TRACE-X",
            "name": "trace",
            "steps": [{"step": 1, "type": "<sink>", "definition": "src/db.py:50"}],
        })
        assert "&lt;SINK&gt;" in out
        assert "&LT;" not in out
        assert "&GT;" not in out

    def test_uppercase_attacker_control_level_preserves_escaped_entities(self):
        out = gen_flow_trace({
            "id": "TRACE-X",
            "name": "trace",
            "steps": [{"step": 1, "type": "entry", "definition": "src/routes.py:10"}],
            "attacker_control": {"level": "<high>", "what": "query"},
        })
        assert "Attacker control: &lt;HIGH&gt;" in out
        assert "&LT;" not in out
        assert "&GT;" not in out


# ---------------------------------------------------------------------------
# attack_tree tests
# ---------------------------------------------------------------------------

class TestAttackTree:
    def test_produces_flowchart_td(self):
        out = gen_attack_tree(ATTACK_TREE_DATA)
        assert out.startswith("flowchart TD")

    def test_all_node_ids_present(self):
        out = gen_attack_tree(ATTACK_TREE_DATA)
        assert "ROOT" in out
        assert "N1" in out
        assert "N2" in out

    def test_edges_from_leads_to(self):
        out = gen_attack_tree(ATTACK_TREE_DATA)
        assert "ROOT --> N1" in out
        assert "ROOT --> N2" in out

    def test_status_style_classes(self):
        out = gen_attack_tree(ATTACK_TREE_DATA)
        assert "classDef confirmed" in out
        assert "classDef disproven" in out
        assert "classDef exploring" in out

    def test_root_node_highlighted(self):
        out = gen_attack_tree(ATTACK_TREE_DATA)
        assert "ROOT" in out and "stroke-width" in out

    def test_empty_nodes(self):
        out = gen_attack_tree({"root": None, "nodes": []})
        assert "No attack tree" in out

    def test_leads_to_empty_string_no_edge(self):
        out = gen_attack_tree(ATTACK_TREE_DATA)
        # N1 and N2 have empty leads_to, so no outgoing edges from them
        lines = out.splitlines()
        n1_edges = [line for line in lines if line.strip().startswith("N1 -->")]
        assert not n1_edges

    def test_confirmed_node_shows_proximity_when_provided(self):
        attack_paths = [{"id": "P1", "finding": "N1", "proximity": 9, "steps": [], "status": "confirmed"}]
        out = gen_attack_tree(ATTACK_TREE_DATA, attack_paths=attack_paths)
        assert "proximity 9/10" in out

    def test_disproven_node_shows_why_wrong_when_provided(self):
        disproven = [{"finding": "N2", "why_wrong": "Error messages suppressed", "lesson": ""}]
        out = gen_attack_tree(ATTACK_TREE_DATA, disproven=disproven)
        assert "ruled out" in out
        assert "suppressed" in out

    def test_enrichment_absent_still_renders(self):
        out = gen_attack_tree(ATTACK_TREE_DATA, attack_paths=None, disproven=None)
        assert "ROOT" in out

    def test_subgraphs_emitted_for_multi_branch_tree(self):
        # ROOT has two children (N1, N2) each with their own children
        tree = {
            "root": "ROOT",
            "nodes": [
                {"id": "ROOT", "goal": "Exploit app", "status": "exploring", "leads_to": "FIND-001,FIND-002"},
                {"id": "FIND-001", "goal": "SQL injection", "status": "confirmed", "leads_to": "N1A,N1B"},
                {"id": "FIND-002", "goal": "Command injection", "status": "exploring", "leads_to": "N2A"},
                {"id": "N1A", "goal": "Direct injection", "status": "confirmed", "leads_to": ""},
                {"id": "N1B", "goal": "Blind injection", "status": "disproven", "leads_to": ""},
                {"id": "N2A", "goal": "Semicolon payload", "status": "exploring", "leads_to": ""},
            ],
        }
        out = gen_attack_tree(tree)
        assert "subgraph" in out
        assert "FIND-001" in out
        assert "FIND-002" in out

    def test_no_subgraphs_for_flat_tree(self):
        # Root has children but none of those children have their own children
        tree = {
            "root": "ROOT",
            "nodes": [
                {"id": "ROOT", "goal": "Exploit", "status": "exploring", "leads_to": "N1,N2"},
                {"id": "N1", "goal": "Path A", "status": "confirmed", "leads_to": ""},
                {"id": "N2", "goal": "Path B", "status": "disproven", "leads_to": ""},
            ],
        }
        out = gen_attack_tree(tree)
        assert "subgraph" not in out


    def test_status_and_hypothesis_enrichment_are_sanitized(self):
        payload = "X\"]\n    click X javascript:alert(1)\n    Y[\""
        tree = {
            "root": "ROOT",
            "nodes": [
                {"id": "ROOT", "goal": "root", "status": payload, "leads_to": "N1"},
                {"id": "N1", "goal": "child", "status": "confirmed", "leads_to": ""},
            ],
        }
        hypotheses = [{"finding": "N1", "status": payload, "claim": payload}]
        assert_no_mermaid_directive_injection(gen_attack_tree(tree, hypotheses=hypotheses))

    def test_status_group_keys_do_not_keep_raw_status_text(self):
        payload = "unexpected<script>"
        tree = {
            "root": "ROOT",
            "nodes": [
                {"id": "ROOT", "goal": "root", "status": payload, "leads_to": "N1"},
                {"id": "N1", "goal": "child", "status": "confirmed", "leads_to": ""},
            ],
        }
        out = gen_attack_tree(tree)
        class_lines = [line for line in out.splitlines() if line.strip().startswith("class ")]
        assert "unexpected<script>" not in "\n".join(class_lines)
        assert any(line.strip() == "class ROOT unexplored" for line in class_lines)


# ---------------------------------------------------------------------------
# hypotheses tests
# ---------------------------------------------------------------------------

class TestHypotheses:
    def test_produces_flowchart_td(self):
        out = gen_hypotheses(HYPOTHESES_DATA)
        assert out.startswith("flowchart TD")

    def test_hypothesis_ids_present(self):
        out = gen_hypotheses(HYPOTHESES_DATA)
        assert "HYPO-001" in out
        assert "HYPO-002" in out

    def test_predictions_present(self):
        out = gen_hypotheses(HYPOTHESES_DATA)
        assert "PRED-001" in out
        assert "PRED-002" in out

    def test_subgraph_per_finding(self):
        out = gen_hypotheses(HYPOTHESES_DATA)
        assert "subgraph" in out
        assert "FIND-001" in out
        assert "FIND-002" in out

    def test_empty_list(self):
        out = gen_hypotheses([])
        assert "No hypotheses" in out

    def test_confirmed_and_disproven_style_classes(self):
        out = gen_hypotheses(HYPOTHESES_DATA)
        assert "classDef confirmed" in out
        assert "classDef disproven" in out

    def test_prediction_edges_present(self):
        out = gen_hypotheses(HYPOTHESES_DATA)
        assert "-->" in out

    def test_no_em_dashes(self):
        out = gen_hypotheses(HYPOTHESES_DATA)
        assert "\u2014" not in out


    def test_subgraph_and_label_fields_are_sanitized(self):
        payload = "F1; click F1 javascript:alert(1)"
        label_payload = "X\"]\n    click X javascript:alert(1)\n    Y[\""
        data = [{
            "id": label_payload,
            "finding": payload,
            "status": label_payload,
            "claim": label_payload,
            "predictions": [
                {"id": label_payload, "prediction": label_payload, "result": label_payload, "status": label_payload}
            ],
        }]
        out = gen_hypotheses(data)
        assert_no_mermaid_directive_injection(out)
        assert "subgraph F1__click_F1_javascript_alert_1_" in out


# ---------------------------------------------------------------------------
# attack_paths tests
# ---------------------------------------------------------------------------

class TestAttackPaths:
    def test_generates_markdown_sections(self):
        out = gen_attack_paths(ATTACK_PATHS_DATA)
        assert "PATH-001" in out
        assert "PATH-002" in out

    def test_proximity_score_shown(self):
        out = gen_attack_paths(ATTACK_PATHS_DATA)
        assert "9/10" in out or "Proximity: 9" in out

    def test_blocker_shown(self):
        out = gen_attack_paths(ATTACK_PATHS_DATA)
        assert "Blocker" in out or "blocked" in out.lower()

    def test_mermaid_fences_present(self):
        out = gen_attack_paths(ATTACK_PATHS_DATA)
        assert "```mermaid" in out

    def test_empty_list(self):
        out = gen_attack_paths([])
        assert "No attack paths" in out

    def test_single_path_step_chain(self):
        out = generate_single(ATTACK_PATHS_DATA[0], 0)
        assert "P0S1" in out
        assert "P0S2" in out
        assert "P0S1 --> P0S2" in out


    def test_step_type_and_location_are_sanitized(self):
        payload = "X\"]\n    click X javascript:alert(1)\n    Y[\""
        out = generate_single({
            "id": "PATH-X",
            "name": payload,
            "status": payload,
            "steps": [
                {
                    "step": 1,
                    "type": payload,
                    "definition": payload,
                    "description": payload,
                    "tainted_var": payload,
                }
            ],
        }, 0)
        assert_no_mermaid_directive_injection(out)

    def test_uppercase_step_type_preserves_escaped_entities(self):
        out = generate_single({
            "id": "PATH-X",
            "name": "path",
            "status": "confirmed",
            "steps": [{"step": 1, "type": "<sink>", "definition": "src/db.py:50"}],
        }, 0)
        assert "&lt;SINK&gt;" in out
        assert "&LT;" not in out
        assert "&GT;" not in out

    def test_sanitized_attack_path_is_still_usable_mermaid(self):
        payload = "X\"]\n    click X javascript:alert(1)\n    Y[\""
        out = generate_single({
            "id": "PATH-X",
            "name": payload,
            "status": "confirmed",
            "proximity": 8,
            "steps": [
                {"step": 1, "type": "entry", "definition": "src/routes.py:10", "description": payload},
                {"step": 2, "type": "sink", "definition": "src/db.py:50", "description": "write"},
            ],
        }, 0)
        assert_no_mermaid_directive_injection(out)
        assert_usable_mermaid_flowchart(out)


# ---------------------------------------------------------------------------
# renderer tests
# ---------------------------------------------------------------------------

class TestRenderer:
    def _make_out_dir(self, tmp_path: Path, files: dict) -> Path:
        for fname, data in files.items():
            (tmp_path / fname).write_text(json.dumps(data), encoding="utf-8")
        return tmp_path

    def test_render_directory_with_context_map(self, tmp_path):
        self._make_out_dir(tmp_path, {"context-map.json": CONTEXT_MAP_FULL})
        out = render_directory(tmp_path, target="testapp")
        assert "Context Map" in out
        assert "testapp" in out
        assert "```mermaid" in out

    def test_render_directory_with_flow_traces(self, tmp_path):
        self._make_out_dir(tmp_path, {"flow-trace-EP-001.json": FLOW_TRACE_DATA})
        out = render_directory(tmp_path)
        assert "Flow Trace" in out or "TRACE-001" in out

    def test_render_directory_with_attack_tree(self, tmp_path):
        self._make_out_dir(tmp_path, {"attack-tree.json": ATTACK_TREE_DATA})
        out = render_directory(tmp_path)
        assert "Attack Tree" in out

    def test_render_directory_with_attack_paths(self, tmp_path):
        self._make_out_dir(tmp_path, {"attack-paths.json": ATTACK_PATHS_DATA})
        out = render_directory(tmp_path)
        assert "Attack Paths" in out

    def test_render_empty_directory(self, tmp_path):
        out = render_directory(tmp_path)
        assert "No renderable" in out

    def test_render_and_write_creates_file(self, tmp_path):
        self._make_out_dir(tmp_path, {"context-map.json": CONTEXT_MAP_FULL})
        out_file = render_and_write(tmp_path, target="myapp")
        assert out_file.exists()
        assert out_file.name == "diagrams.md"
        content = out_file.read_text()
        assert "```mermaid" in content

    def test_render_all_types_combined(self, tmp_path):
        self._make_out_dir(tmp_path, {
            "context-map.json": CONTEXT_MAP_FULL,
            "flow-trace-EP-001.json": FLOW_TRACE_DATA,
            "attack-tree.json": ATTACK_TREE_DATA,
            "attack-paths.json": ATTACK_PATHS_DATA,
            "hypotheses.json": HYPOTHESES_DATA,
        })
        out = render_directory(tmp_path, target="full-run")
        assert "Context Map" in out
        assert "Attack Tree" in out
        assert "Attack Paths" in out
        assert "Hypotheses" in out
        assert out.count("```mermaid") >= 5

    def test_rendered_mermaid_blocks_have_usable_entrypoints(self, tmp_path):
        self._make_out_dir(tmp_path, {
            "context-map.json": CONTEXT_MAP_FULL,
            "flow-trace-EP-001.json": FLOW_TRACE_DATA,
            "attack-tree.json": ATTACK_TREE_DATA,
            "attack-paths.json": ATTACK_PATHS_DATA,
            "hypotheses.json": HYPOTHESES_DATA,
            "findings.json": {
                "findings": [
                    {"ruling": {"status": "exploitable"}, "vuln_type": "buffer_overflow"},
                    {"ruling": {"status": "confirmed"}, "vuln_type": "xss"},
                ]
            },
        })
        blocks = extract_mermaid_blocks(render_directory(tmp_path, target="full-run"))
        assert blocks
        assert all(
            block.startswith(("flowchart TD", "flowchart LR", "pie title", "%%{init:"))
            for block in blocks
        )
        assert all("\n```" not in block for block in blocks)

    def test_render_attack_tree_enriched_with_companions(self, tmp_path):
        disproven_wrapped = {"disproven": [{"finding": "N2", "why_wrong": "suppressed errors", "lesson": ""}]}
        self._make_out_dir(tmp_path, {
            "attack-tree.json": ATTACK_TREE_DATA,
            "attack-paths.json": ATTACK_PATHS_DATA,
            "disproven.json": disproven_wrapped,
            "hypotheses.json": HYPOTHESES_DATA,
        })
        out = render_directory(tmp_path)
        assert "Attack Tree" in out
        assert "enriched" in out

    def test_render_hypotheses(self, tmp_path):
        self._make_out_dir(tmp_path, {"hypotheses.json": HYPOTHESES_DATA})
        out = render_directory(tmp_path)
        assert "Hypotheses" in out
        assert "HYPO-001" in out

    def test_render_findings_summary_pies(self, tmp_path):
        self._make_out_dir(tmp_path, {"findings.json": {
            "findings": [
                {"ruling": {"status": "exploitable"}, "vuln_type": "buffer_overflow"},
                {"ruling": {"status": "confirmed"}, "vuln_type": "buffer_overflow"},
                {"ruling": {"status": "ruled_out"}, "vuln_type": "xss"},
            ]
        }})
        out = render_directory(tmp_path)
        assert "Findings Summary" in out
        assert "Finding Verdicts" in out
        assert "Vulnerability Types" in out
        assert out.count("pie title") == 2

    def test_corrupt_json_handled_gracefully(self, tmp_path):
        (tmp_path / "context-map.json").write_text("{corrupt json", encoding="utf-8")
        out = render_directory(tmp_path)
        assert "Could not render" in out
