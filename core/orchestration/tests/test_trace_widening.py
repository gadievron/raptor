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


class _FakeAssumption:
    def __init__(self, enforced_by):
        self.enforced_by = enforced_by


class TestEnrichTraceWithAssumptionFilter:
    def test_marks_siblings_lacking_enforcer(self):
        from core.orchestration.trace_widening import enrich_trace_with_assumption_filter

        cl = {
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
                            {"caller": "handle_admin", "chain": ["validate"], "line": 90},
                        ],
                    },
                },
                {
                    "path": "src/admin/bulk.py",
                    "functions": [{"name": "bulk_import", "line": 5}],
                    "call_graph": {
                        "calls": [
                            {"caller": "bulk_import", "chain": ["run_query"], "line": 15},
                        ],
                    },
                },
            ],
        }
        trace = {
            "steps": [
                {"step": 1, "type": "entry", "function": "handle_query",
                 "definition": "src/routes/query.py:34"},
                {"step": 2, "type": "call", "function": "run_query",
                 "definition": "src/services/query_service.py:12"},
            ],
        }
        assumptions = [_FakeAssumption(enforced_by=["validate"])]
        enriched = enrich_trace_with_assumption_filter(trace, cl, assumptions)

        siblings = enriched["steps"][1].get("siblings", [])
        assert len(siblings) >= 1

        by_func = {s["function"]: s for s in siblings}
        if "handle_admin" in by_func:
            assert by_func["handle_admin"].get("lacks_enforcer") is not True
        if "bulk_import" in by_func:
            assert by_func["bulk_import"].get("lacks_enforcer") is True

    def test_no_assumptions_leaves_siblings_unchanged(self):
        from core.orchestration.trace_widening import enrich_trace_with_assumption_filter

        cl = _checklist_with_calls()
        trace = _trace_data()
        enriched = enrich_trace_with_assumption_filter(trace, cl, [])

        step2 = enriched["steps"][1]
        siblings = step2.get("siblings", [])
        for s in siblings:
            assert "lacks_enforcer" not in s

    def test_empty_enforced_by_skips_marking(self):
        from core.orchestration.trace_widening import enrich_trace_with_assumption_filter

        cl = _checklist_with_calls()
        trace = _trace_data()
        assumptions = [_FakeAssumption(enforced_by=[])]
        enriched = enrich_trace_with_assumption_filter(trace, cl, assumptions)

        step2 = enriched["steps"][1]
        for s in step2.get("siblings", []):
            assert "lacks_enforcer" not in s


class TestSpanContainmentResolution:
    """Definition points resolve by span containment, never by
    nearest line_start (which attributed points inside one function
    to a closer-starting neighbour and failed >20 lines into any
    long body)."""

    _CHECKLIST = {"files": [{"path": "src/x.c", "items": [
        {"name": "func_A", "line_start": 50, "line_end": 200},
        {"name": "func_B", "line_start": 110, "line_end": 260},
    ]}]}

    def test_point_inside_span_resolves_to_container(self):
        from core.orchestration.trace_widening import (
            _resolve_function_from_checklist,
        )
        # 100 sits inside func_A (50-200); func_B merely STARTS
        # closer (110).
        assert _resolve_function_from_checklist(
            "src/x.c:100", self._CHECKLIST) == "func_A"

    def test_deep_point_in_long_body_still_resolves(self):
        from core.orchestration.trace_widening import (
            _resolve_function_from_checklist,
        )
        # 80 is >20 lines past func_A's start — the old +-20 window
        # returned None.
        assert _resolve_function_from_checklist(
            "src/x.c:80", self._CHECKLIST) == "func_A"

    def test_overlap_innermost_wins(self):
        from core.orchestration.trace_widening import (
            _resolve_function_from_checklist,
        )
        # 150 is inside both spans; the innermost (larger line_start)
        # wins, matching enclosing_function semantics.
        assert _resolve_function_from_checklist(
            "src/x.c:150", self._CHECKLIST) == "func_B"

    def test_point_outside_every_span_is_none(self):
        from core.orchestration.trace_widening import (
            _resolve_function_from_checklist,
        )
        assert _resolve_function_from_checklist(
            "src/x.c:20", self._CHECKLIST) is None

    def test_missing_line_end_falls_back_to_preceding_start(self):
        from core.orchestration.trace_widening import (
            _resolve_function_from_checklist,
        )
        checklist = {"files": [{"path": "src/y.c", "items": [
            {"name": "early", "line_start": 10},
            {"name": "late", "line_start": 90},
        ]}]}
        assert _resolve_function_from_checklist(
            "src/y.c:60", checklist) == "early"
        assert _resolve_function_from_checklist(
            "src/y.c:95", checklist) == "late"

    def test_legacy_functions_key_and_line_field(self):
        from core.orchestration.trace_widening import (
            _resolve_function_from_checklist,
        )
        checklist = {"files": [{"path": "src/z.c", "functions": [
            {"name": "handler", "line": 30},
        ]}]}
        assert _resolve_function_from_checklist(
            "src/z.c:35", checklist) == "handler"
