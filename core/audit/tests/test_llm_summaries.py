"""Tests for core.audit.llm_summaries — pre-loop LLM summary extraction."""

from core.audit.llm_summaries import (
    _parse_summary_response,
    identify_summary_candidates,
)


class TestIdentifySummaryCandidates:
    def test_connected_functions_without_summaries(self):
        workqueue = [
            {"file": "a.c", "name": "caller", "callees": [{"name": "callee", "file": "a.c"}]},
            {"file": "a.c", "name": "callee", "callees": []},
        ]
        candidates = identify_summary_candidates(workqueue, {}, None)
        keys = {f"{c['file']}:{c['name']}" for c in candidates}
        assert "a.c:caller" in keys
        assert "a.c:callee" in keys

    def test_already_summarised_excluded(self):
        workqueue = [
            {"file": "a.c", "name": "caller", "callees": [{"name": "callee", "file": "a.c"}]},
            {"file": "a.c", "name": "callee", "callees": []},
        ]
        existing = {"a.c:callee": object()}
        candidates = identify_summary_candidates(workqueue, existing, None)
        keys = {f"{c['file']}:{c['name']}" for c in candidates}
        assert "a.c:callee" not in keys
        assert "a.c:caller" in keys

    def test_disconnected_functions_excluded(self):
        workqueue = [
            {"file": "a.c", "name": "lone", "callees": []},
            {"file": "b.c", "name": "other", "callees": []},
        ]
        candidates = identify_summary_candidates(workqueue, {}, None)
        assert candidates == []

    def test_empty_workqueue(self):
        assert identify_summary_candidates([], {}, None) == []

    def test_string_callee_format(self):
        workqueue = [
            {"file": "a.c", "name": "caller", "callees": ["callee"]},
            {"file": "a.c", "name": "callee", "callees": []},
        ]
        candidates = identify_summary_candidates(workqueue, {}, None)
        # String callees don't carry file info, so "a.c:callee" won't match ":callee"
        # This tests the string-callee branch doesn't crash
        assert isinstance(candidates, list)

    def test_respects_max_cap(self):
        workqueue = []
        for i in range(200):
            workqueue.append({
                "file": "a.c", "name": f"f{i}",
                "callees": [{"name": f"f{(i + 1) % 200}", "file": "a.c"}],
                "priority_score": float(i),
            })
        candidates = identify_summary_candidates(workqueue, {}, None)
        assert len(candidates) <= 80


class TestParseSummaryResponse:
    def test_valid_json(self):
        text = '''{
            "preconditions": [
                {"parameter": "buf", "assumption": "must not be NULL"}
            ],
            "taint_flows": [
                {"source_param": "buf", "source_index": 0,
                 "sink_call": "memcpy", "sink_arg_index": 1}
            ],
            "callees": ["util.c:validate"],
            "callers": [],
            "error_paths": ["return -1"],
            "state_transitions": ["acquires lock"]
        }'''
        s = _parse_summary_response(text, "parse", "net.c")
        assert s is not None
        assert s.function == "parse"
        assert s.file == "net.c"
        assert len(s.preconditions) == 1
        assert s.preconditions[0].param == "buf"
        assert len(s.taint_rules) == 1
        assert s.taint_rules[0].sink_call == "memcpy"
        assert s.callees == ["util.c:validate"]
        assert s.error_paths == ["return -1"]
        assert s.state_transitions == ["acquires lock"]
        assert s.source == "llm"
        assert s.confidence == "medium"

    def test_json_with_markdown_fences(self):
        text = '```json\n{"preconditions": [{"parameter": "x", "assumption": "> 0"}]}\n```'
        s = _parse_summary_response(text, "f", "a.c")
        assert s is not None
        assert len(s.preconditions) == 1

    def test_json_embedded_in_text(self):
        text = 'Here is the analysis:\n{"preconditions": [{"parameter": "p", "assumption": "not null"}]}\nDone.'
        s = _parse_summary_response(text, "f", "a.c")
        assert s is not None
        assert len(s.preconditions) == 1

    def test_empty_summary(self):
        text = '{"preconditions": [], "taint_flows": [], "callees": [], "callers": [], "error_paths": []}'
        s = _parse_summary_response(text, "f", "a.c")
        assert s is not None
        assert s.is_empty()

    def test_invalid_json(self):
        s = _parse_summary_response("not json at all", "f", "a.c")
        assert s is None

    def test_non_dict_json(self):
        s = _parse_summary_response("[1, 2, 3]", "f", "a.c")
        assert s is None

    def test_preserves_long_lists(self):
        import json as _json
        callees = [f"f{i}" for i in range(50)]
        text = _json.dumps({"callees": callees, "preconditions": [{"parameter": "x", "assumption": "y"}]})
        s = _parse_summary_response(text, "f", "a.c")
        assert s is not None
        assert len(s.callees) == 50

    def test_alternative_field_names(self):
        text = '{"preconditions": [{"param": "buf", "condition": "!= NULL"}]}'
        s = _parse_summary_response(text, "f", "a.c")
        assert s is not None
        assert s.preconditions[0].param == "buf"
        assert s.preconditions[0].conditions == ["!= NULL"]
