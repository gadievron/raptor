"""Tests for core.orchestration.joern_trace."""

from __future__ import annotations

from core.orchestration.joern_trace import (
    enrich_trace_with_joern,
    extract_source_sink,
)


class FakeFlow:
    def __init__(self, steps):
        self.steps = steps


class FakeServer:
    """Records taint queries; answers from a canned flow map."""

    def __init__(self, flows=None, error=False):
        self.flows = flows or {}
        self.error = error
        self.queries = []

    def run_taint_query(self, source_method, sink_call, **kwargs):
        self.queries.append((source_method, sink_call))
        if self.error:
            raise RuntimeError("joern down")
        return self.flows.get((source_method, sink_call), [])


def _trace():
    return {
        "id": "TRACE-001",
        "name": "main → memcpy",
        "meta": {
            "entry_point": "main",
            "entry_file": "entry.c:70",
            "target_sink": "memcpy",
        },
        "steps": [
            {"step": 1, "type": "entry", "definition": "entry.c:70"},
            {
                "step": 2,
                "type": "sink",
                "call_site": "entry.c:25",
                "definition": "memcpy(out, buf + 1, claimed)",
                "sink_type": "buffer_write",
            },
        ],
        "summary": {"flow_confirmed": True, "confidence": "high"},
    }


def _flow():
    return FakeFlow(steps=[
        {"file": "entry.c", "line": 70, "code": "fread(buf, ...)",
         "function": "main"},
        {"file": "entry.c", "line": 25, "code": "memcpy(out, buf + 1, n)",
         "function": "parse_alpha"},
    ])


class TestExtractSourceSink:
    def test_identifier_names_pass_through(self):
        assert extract_source_sink(_trace()) == ("main", "memcpy")

    def test_route_string_entry_point_unresolvable(self):
        trace = _trace()
        trace["meta"]["entry_point"] = "POST /api/v2/query"
        source, sink = extract_source_sink(trace)
        assert source is None
        assert sink == "memcpy"

    def test_sink_parsed_from_sink_step_definition(self):
        trace = _trace()
        trace["meta"]["target_sink"] = "raw SQL execution"
        _, sink = extract_source_sink(trace)
        assert sink == "memcpy"

    def test_call_name_parsed_from_target_sink(self):
        trace = _trace()
        trace["meta"]["target_sink"] = "psycopg2.cursor.execute()"
        del trace["steps"]
        _, sink = extract_source_sink(trace)
        assert sink == "execute"


class TestEnrichTraceWithJoern:
    def test_confirmed_flow_annotates_and_upgrades(self):
        trace = _trace()
        srv = FakeServer(flows={("main", "memcpy"): [_flow()]})
        enrich_trace_with_joern(trace, srv)

        verification = trace["joern_verification"]
        assert verification["verified"] is True
        assert verification["joern_flow_count"] == 1
        assert verification["joern_steps"][0]["line"] == 70
        assert verification["joern_steps"][-1]["function"] == "parse_alpha"
        assert verification["previous_confidence"] == "high"
        assert trace["summary"]["confidence"] == "mechanically_confirmed"

    def test_refuted_flow_downgrades_confidence(self):
        trace = _trace()
        enrich_trace_with_joern(trace, FakeServer())
        assert trace["joern_verification"]["verified"] is False
        assert trace["joern_verification"]["joern_flow_count"] == 0
        assert trace["summary"]["confidence"] == "mechanical_refuted"

    def test_explicit_names_override_extraction(self):
        trace = _trace()
        srv = FakeServer()
        enrich_trace_with_joern(
            trace, srv, source_method="handle_req", sink_call="strcpy")
        assert srv.queries == [("handle_req", "strcpy")]

    def test_unresolvable_names_skip_with_reason(self):
        trace = _trace()
        trace["meta"] = {"entry_point": "POST /q", "target_sink": "raw SQL"}
        trace["steps"] = []
        srv = FakeServer()
        enrich_trace_with_joern(trace, srv)
        assert srv.queries == []
        assert trace["joern_verification"]["verified"] is None
        assert "skipped" in trace["joern_verification"]
        # Confidence untouched when nothing was verified.
        assert trace["summary"]["confidence"] == "high"

    def test_query_error_degrades_to_skipped(self):
        trace = _trace()
        enrich_trace_with_joern(trace, FakeServer(error=True))
        assert trace["joern_verification"]["verified"] is None
        assert trace["summary"]["confidence"] == "high"


class TestIdentifierFullmatch:
    def test_trailing_newline_rejected(self):
        # fullmatch: a $-anchored match() admits "main\n".
        from core.orchestration.joern_trace import _is_identifier
        assert _is_identifier("main") is True
        assert _is_identifier("main\n") is False
        assert _is_identifier("os.system\n") is False

    def test_trailing_newline_entry_point_unresolvable(self):
        trace = _trace()
        trace["meta"]["entry_point"] = "main\n"
        trace["meta"]["target_sink"] = "memcpy"
        source, sink = extract_source_sink(trace)
        assert source is None
        assert sink == "memcpy"
