"""Tests for Phase E: trace widening via CompositionalAnalyzer."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from core.inventory.call_graph import CallSite, FileCallGraph
from core.iris.trace_widening import (
    _extract_assumptions,
    _parse_definition,
    _sink_cwe,
    _step_function_name,
    widen_dir,
    widen_trace,
)


def _graph(calls):
    return FileCallGraph(
        calls=[
            CallSite(line=line, chain=[callee], caller=caller)
            for caller, callee, line in calls
        ],
    )


def _trace(steps=None, sanitizers=None):
    return {
        "id": "TRACE-001",
        "name": "test trace",
        "steps": steps or [],
        "summary": {
            "flow_confirmed": True,
            "sanitizers": sanitizers or [],
            "verdict": "test",
        },
    }


class TestParseDefinition:
    def test_file_line(self):
        f, fn = _parse_definition("src/app.py:42")
        assert f == "src/app.py"
        assert fn == ""

    def test_dotted_method(self):
        f, fn = _parse_definition("psycopg2.cursor.execute()")
        assert fn == "execute"

    def test_plain_name(self):
        f, fn = _parse_definition("my_func()")
        assert fn == "my_func"

    def test_empty(self):
        assert _parse_definition("") == ("", "")


class TestStepFunctionName:
    def test_from_ast_view(self):
        step = {"definition": "src/app.py:42", "ast_view": {"name": "handle_request"}}
        assert _step_function_name(step) == "handle_request"

    def test_from_dotted_definition(self):
        step = {"definition": "psycopg2.cursor.execute()"}
        assert _step_function_name(step) == "execute"

    def test_from_function_field(self):
        step = {"definition": "src/app.py:42", "function": "handle_request"}
        assert _step_function_name(step) == "handle_request"

    def test_empty(self):
        assert _step_function_name({}) == ""


class TestSinkCwe:
    def test_known_types(self):
        assert _sink_cwe("db_query") == "CWE-89"
        assert _sink_cwe("shell") == "CWE-78"
        assert _sink_cwe("file") == "CWE-22"

    def test_unknown_type(self):
        assert _sink_cwe("unknown") == ""


class TestExtractAssumptions:
    def test_sanitiser_step_creates_assumption(self):
        trace = _trace(
            steps=[
                {"step": 1, "type": "entry", "definition": "src/routes.py:10",
                 "transform": "none"},
                {"step": 2, "type": "call", "definition": "html.escape()",
                 "transform": "sanitize_html"},
                {"step": 3, "type": "sink", "definition": "db.cursor.execute()",
                 "sink_type": "db_query", "transform": "none"},
            ],
        )
        assumptions = _extract_assumptions(trace)
        assert len(assumptions) == 1
        assert assumptions[0].target == "execute"
        assert "escape" in assumptions[0].enforced_by[0]

    def test_no_sanitiser_no_assumption(self):
        trace = _trace(
            steps=[
                {"step": 1, "type": "entry", "definition": "src/routes.py:10",
                 "transform": "none"},
                {"step": 2, "type": "sink", "definition": "db.cursor.execute()",
                 "sink_type": "db_query", "transform": "none"},
            ],
        )
        assumptions = _extract_assumptions(trace)
        assert len(assumptions) == 0

    def test_summary_sanitizers_used(self):
        trace = _trace(
            steps=[
                {"step": 1, "type": "entry", "definition": "src/app.py:1",
                 "transform": "none"},
                {"step": 2, "type": "sink", "definition": "db.cursor.execute()",
                 "sink_type": "db_query", "transform": "none"},
            ],
            sanitizers=["html_escape"],
        )
        assumptions = _extract_assumptions(trace)
        assert len(assumptions) == 1
        assert "html_escape" in assumptions[0].enforced_by

    def test_ast_view_preferred_for_name(self):
        trace = _trace(
            steps=[
                {"step": 1, "type": "entry", "definition": "src/app.py:10",
                 "ast_view": {"name": "handle_post"}, "transform": "none"},
                {"step": 2, "type": "call", "definition": "src/sanitise.py:20",
                 "ast_view": {"name": "sanitise_html"}, "transform": "validate"},
                {"step": 3, "type": "sink", "definition": "src/db.py:30",
                 "ast_view": {"name": "run_query"}, "sink_type": "db_query",
                 "transform": "none"},
            ],
        )
        assumptions = _extract_assumptions(trace)
        assert len(assumptions) == 1
        assert assumptions[0].target == "run_query"
        assert "sanitise_html" in assumptions[0].enforced_by


class TestWidenTrace:
    def test_widen_finds_bypass_callers(self):
        graphs = {
            "src/db.py": _graph([
                ("safe_handler", "escape_html", 10),
                ("safe_handler", "execute", 20),
                ("unsafe_handler", "execute", 30),
            ]),
        }
        trace = _trace(
            steps=[
                {"step": 1, "type": "entry", "definition": "src/routes.py:10",
                 "ast_view": {"name": "handle_post"}, "transform": "none"},
                {"step": 2, "type": "call", "definition": "html.escape_html()",
                 "transform": "sanitize input"},
                {"step": 3, "type": "sink", "definition": "db.cursor.execute()",
                 "sink_type": "db_query", "transform": "none"},
            ],
        )

        with patch("core.inventory.call_graph.load_call_graphs", return_value=graphs):
            candidates = widen_trace(trace, Path("/fake/target"))

        assert trace.get("widening") is not None
        assert isinstance(trace["widening"], list)
        bypass_callers = {c["caller_function"] for c in candidates}
        assert "unsafe_handler" in bypass_callers

    def test_widen_empty_on_no_steps(self):
        trace = _trace(steps=[])
        candidates = widen_trace(trace, Path("/fake"))
        assert candidates == []
        assert "widening" not in trace

    def test_widen_sets_empty_list_when_no_bypasses(self):
        graphs = {
            "src/db.py": _graph([
                ("safe_handler", "escape_html", 10),
                ("safe_handler", "execute", 20),
            ]),
        }
        trace = _trace(
            steps=[
                {"step": 1, "type": "entry", "definition": "src/routes.py:10",
                 "transform": "none"},
                {"step": 2, "type": "call", "definition": "html.escape_html()",
                 "transform": "sanitize"},
                {"step": 3, "type": "sink", "definition": "db.cursor.execute()",
                 "sink_type": "db_query", "transform": "none"},
            ],
        )
        with patch("core.inventory.call_graph.load_call_graphs", return_value=graphs):
            widen_trace(trace, Path("/fake"))
        assert trace["widening"] == []


class TestWidenDir:
    def test_processes_trace_files(self):
        graphs = {
            "src/app.c": _graph([
                ("safe_caller", "validate", 10),
                ("safe_caller", "exec_cmd", 20),
                ("unsafe_caller", "exec_cmd", 30),
            ]),
        }
        trace = _trace(
            steps=[
                {"step": 1, "type": "entry", "definition": "src/app.c:1",
                 "ast_view": {"name": "handle"}, "transform": "none"},
                {"step": 2, "type": "call", "definition": "lib.validate()",
                 "transform": "validate input"},
                {"step": 3, "type": "sink", "definition": "os.exec_cmd()",
                 "sink_type": "shell", "transform": "none"},
            ],
        )
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "flow-trace-001.json"
            p.write_text(json.dumps(trace))

            with patch("core.inventory.call_graph.load_call_graphs", return_value=graphs):
                total = widen_dir(Path(td), Path("/fake"))

            reloaded = json.loads(p.read_text())
            assert "widening" in reloaded
            assert total >= 1

    def test_skips_already_widened(self):
        trace = _trace(
            steps=[
                {"step": 1, "type": "entry", "definition": "src/app.py:1",
                 "ast_view": {"name": "handle"}, "transform": "none"},
                {"step": 2, "type": "call", "definition": "lib.validate()",
                 "transform": "sanitize input"},
                {"step": 3, "type": "sink", "definition": "os.exec_cmd()",
                 "sink_type": "shell", "transform": "none"},
            ],
        )
        trace["widening"] = []
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "flow-trace-001.json"
            p.write_text(json.dumps(trace))
            total = widen_dir(Path(td), Path("/fake"))
            assert total == 0
