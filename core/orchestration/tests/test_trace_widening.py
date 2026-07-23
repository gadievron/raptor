"""Tests for core.orchestration.trace_widening."""

from __future__ import annotations

import json

from core.orchestration.trace_widening import (
    _build_reverse_call_map,
    enrich_all_traces,
    enrich_trace_with_siblings,
)


def _checklist_with_calls():
    """Minimal checklist with call graph data."""
    return {
        "files": [
            {
                "path": "src/routes/query.py",
                "functions": [
                    {"name": "handle_query", "line": 34},
                    {"name": "handle_admin", "line": 80},
                ],
                "call_graph": {
                    "calls": [
                        {"caller": "handle_query", "chain": ["run_query"], "line": 48},
                        {"caller": "handle_admin", "chain": ["run_query"], "line": 92},
                    ],
                },
            },
            {
                "path": "src/services/query_service.py",
                "functions": [
                    {"name": "run_query", "line": 12},
                ],
                "call_graph": {
                    "calls": [
                        {"caller": "run_query", "chain": ["execute"], "line": 31},
                    ],
                },
            },
            {
                "path": "src/admin/bulk.py",
                "functions": [
                    {"name": "bulk_import", "line": 5},
                ],
                "call_graph": {
                    "calls": [
                        {"caller": "bulk_import", "chain": ["run_query"], "line": 15},
                    ],
                },
            },
        ],
    }


def _trace_data():
    """A flow trace through handle_query → run_query → execute."""
    return {
        "id": "TRACE-001",
        "steps": [
            {
                "step": 1,
                "type": "entry",
                "definition": "src/routes/query.py:34",
                "function": "handle_query",
                "tainted_var": "query",
            },
            {
                "step": 2,
                "type": "call",
                "call_site": "src/routes/query.py:48",
                "definition": "src/services/query_service.py:12",
                "function": "run_query",
                "tainted_var": "query_str",
            },
            {
                "step": 3,
                "type": "sink",
                "call_site": "src/services/query_service.py:31",
                "definition": "psycopg2.cursor.execute()",
                "function": "execute",
                "tainted_var": "query_str",
            },
        ],
    }


class TestBuildReverseCallMap:
    def test_builds_callers(self):
        cl = _checklist_with_calls()
        reverse = _build_reverse_call_map(cl)
        assert "run_query" in reverse
        callers = [c["function"] for c in reverse["run_query"]]
        assert "handle_query" in callers
        assert "handle_admin" in callers
        assert "bulk_import" in callers

    def test_empty_checklist(self):
        assert _build_reverse_call_map({}) == {}
        assert _build_reverse_call_map({"files": []}) == {}


class TestEnrichTraceWithSiblings:
    def test_adds_siblings_to_intermediate_step(self):
        trace = _trace_data()
        cl = _checklist_with_calls()
        enriched = enrich_trace_with_siblings(trace, cl)

        step2 = enriched["steps"][1]
        assert "siblings" in step2
        sibling_funcs = [s["function"] for s in step2["siblings"]]
        assert "handle_admin" in sibling_funcs
        assert "bulk_import" in sibling_funcs
        assert "handle_query" not in sibling_funcs

    def test_entry_step_has_no_siblings(self):
        trace = _trace_data()
        cl = _checklist_with_calls()
        enriched = enrich_trace_with_siblings(trace, cl)
        assert "siblings" not in enriched["steps"][0]

    def test_no_siblings_when_no_other_callers(self):
        cl = {
            "files": [{
                "path": "a.py",
                "functions": [{"name": "f", "line": 1}],
                "call_graph": {
                    "calls": [{"caller": "f", "chain": ["g"], "line": 5}],
                },
            }],
        }
        trace = {
            "steps": [
                {"step": 1, "type": "entry", "definition": "a.py:1", "function": "f"},
                {"step": 2, "type": "call", "definition": "a.py:10", "function": "g"},
            ],
        }
        enriched = enrich_trace_with_siblings(trace, cl)
        assert "siblings" not in enriched["steps"][1]

    def test_empty_steps(self):
        assert enrich_trace_with_siblings({"steps": []}, {}) == {"steps": []}

    def test_deduplicates_siblings(self):
        cl = {
            "files": [{
                "path": "a.py",
                "functions": [{"name": "caller_a", "line": 1}],
                "call_graph": {
                    "calls": [
                        {"caller": "caller_a", "chain": ["target"], "line": 5},
                        {"caller": "caller_a", "chain": ["target"], "line": 8},
                    ],
                },
            }],
        }
        trace = {
            "steps": [
                {"step": 1, "type": "entry", "definition": "x.py:1", "function": "main"},
                {"step": 2, "type": "call", "definition": "a.py:10", "function": "target"},
            ],
        }
        enriched = enrich_trace_with_siblings(trace, cl)
        if enriched["steps"][1].get("siblings"):
            funcs = [s["function"] for s in enriched["steps"][1]["siblings"]]
            assert len(funcs) == len(set(funcs))


class TestEnrichAllTraces:
    def test_enriches_files(self, tmp_path):
        cl = _checklist_with_calls()
        trace = _trace_data()

        trace_path = tmp_path / "flow-trace-001.json"
        trace_path.write_text(json.dumps(trace), encoding="utf-8")

        count = enrich_all_traces(tmp_path, cl)
        assert count == 1

        enriched = json.loads(trace_path.read_text(encoding="utf-8"))
        assert "siblings" in enriched["steps"][1]

    def test_skips_non_trace_files(self, tmp_path):
        (tmp_path / "context-map.json").write_text("{}", encoding="utf-8")
        count = enrich_all_traces(tmp_path, {"files": []})
        assert count == 0

    def test_skips_malformed_json(self, tmp_path):
        (tmp_path / "flow-trace-bad.json").write_text("not json", encoding="utf-8")
        count = enrich_all_traces(tmp_path, {"files": []})
        assert count == 0
