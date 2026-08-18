"""Tests for the IRIS refinement Joern ToolRunner.

Regression: the runner passed the compiled Joern *config text* as
``joern_live_query``'s ``function_name`` and omitted the required
``sinks`` argument — every live-tool refinement round crashed inside
the refine loop's error handler and specs never earned XREF_BACKED
tier from Joern.  The runner now fires targeted source→sink taint
queries per spec pair and reports confirmations keyed by the
persistent-store spec key.
"""

from __future__ import annotations

from core.audit.orchestrator import (
    _IRIS_JOERN_PAIR_BUDGET,
    _make_iris_joern_tool_runner,
)
from core.iris.refine import RefinementFeedback
from core.iris.specs import TaintSpec
from core.iris.store import _spec_key


class _FakeServer:
    """Live-server stand-in recording taint queries."""

    def __init__(self, flows_for: set[tuple[str, str]] | None = None):
        self.calls: list[tuple[str, str]] = []
        self._flows_for = flows_for or set()

    def run_taint_query(self, source_method, sink_call, **kwargs):
        self.calls.append((source_method, sink_call))
        if (source_method, sink_call) in self._flows_for:
            return [{"source": source_method, "sink": sink_call}]
        return []


def _spec(function: str, role: str, file: str = "app.py") -> TaintSpec:
    return TaintSpec(function=function, file=file, role=role)


class TestIrisJoernToolRunner:
    def test_flow_confirms_both_endpoint_specs(self):
        source = _spec("read_input", "source")
        sink = _spec("run_query", "sink")
        server = _FakeServer(flows_for={("read_input", "run_query")})
        runner = _make_iris_joern_tool_runner(server)

        feedback = runner([source, sink])

        assert isinstance(feedback, RefinementFeedback)
        assert set(feedback.confirmed_keys) == {
            _spec_key(source), _spec_key(sink),
        }
        assert server.calls == [("read_input", "run_query")]

    def test_no_flows_confirms_nothing(self):
        server = _FakeServer()
        runner = _make_iris_joern_tool_runner(server)

        feedback = runner([
            _spec("read_input", "source"),
            _spec("run_query", "sink"),
        ])

        assert feedback.confirmed_keys == []
        assert feedback.tool_errors == []

    def test_non_endpoint_roles_short_circuit(self):
        """Sanitiser/propagator-only spec sets never hit the server."""
        server = _FakeServer()
        runner = _make_iris_joern_tool_runner(server)

        feedback = runner([
            _spec("escape_html", "sanitiser"),
            _spec("wrap", "propagator"),
        ])

        assert feedback.confirmed_keys == []
        assert server.calls == []

    def test_pair_walk_is_budgeted(self):
        n = 12  # 12 x 12 = 144 pairs > budget
        specs = (
            [_spec(f"src_{i}", "source") for i in range(n)]
            + [_spec(f"snk_{i}", "sink") for i in range(n)]
        )
        server = _FakeServer()
        runner = _make_iris_joern_tool_runner(server)

        runner(specs)

        assert len(server.calls) == _IRIS_JOERN_PAIR_BUDGET

    def test_confirmed_keys_deduplicated(self):
        """A source flowing into two sinks is confirmed once."""
        source = _spec("read_input", "source")
        sink_a = _spec("run_query", "sink")
        sink_b = _spec("exec_cmd", "sink")
        server = _FakeServer(flows_for={
            ("read_input", "run_query"),
            ("read_input", "exec_cmd"),
        })
        runner = _make_iris_joern_tool_runner(server)

        feedback = runner([source, sink_a, sink_b])

        assert feedback.confirmed_keys.count(_spec_key(source)) == 1
        assert set(feedback.confirmed_keys) == {
            _spec_key(source), _spec_key(sink_a), _spec_key(sink_b),
        }
