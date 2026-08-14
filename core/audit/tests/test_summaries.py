"""Tests for core.audit.summaries — function summary extraction."""

from core.analysis.summaries import (
    FunctionSummary,
    Precondition,
    ReturnCondition,
    TaintRule,
    build_summary_from_query_outputs,
    parse_error_lines,
    parse_guard_lines,
    parse_return_lines,
    parse_taint_lines,
    propagate_taint_upward,
    resolve_scc_summaries,
)
from core.evidence import EvidenceTier


class TestTaintRule:
    def test_fields(self):
        r = TaintRule(
            source_param="buf", source_index=0,
            sink_call="memcpy", sink_arg_index=1, hop_count=3,
        )
        assert r.source_param == "buf"
        assert r.sink_call == "memcpy"
        assert r.hop_count == 3


class TestParseTaintLines:
    def test_valid_line(self):
        raw = 'SUMMARY_TAINT: {"source_param": "buf", "source_index": 0, "sink_call": "memcpy", "sink_arg_index": 1, "hop_count": 2}'
        rules = parse_taint_lines(raw)
        assert len(rules) == 1
        assert rules[0].source_param == "buf"
        assert rules[0].sink_call == "memcpy"
        assert rules[0].hop_count == 2

    def test_multiple_lines(self):
        raw = (
            'SUMMARY_TAINT: {"source_param": "a", "source_index": 0, "sink_call": "f", "sink_arg_index": 0, "hop_count": 1}\n'
            'some other output\n'
            'SUMMARY_TAINT: {"source_param": "b", "source_index": 1, "sink_call": "g", "sink_arg_index": 0, "hop_count": 1}\n'
        )
        rules = parse_taint_lines(raw)
        assert len(rules) == 2

    def test_ignores_non_taint_lines(self):
        raw = "JOERN_FLOW: something\nrandom output"
        assert parse_taint_lines(raw) == []

    def test_malformed_json_skipped(self):
        raw = "SUMMARY_TAINT: not json"
        assert parse_taint_lines(raw) == []


class TestParseGuardLines:
    def test_valid_line(self):
        raw = 'SUMMARY_GUARD: {"param": "len", "param_index": 1, "conditions": ["len < MAX"]}'
        guards = parse_guard_lines(raw)
        assert len(guards) == 1
        assert guards[0].param == "len"
        assert guards[0].conditions == ["len < MAX"]

    def test_empty(self):
        assert parse_guard_lines("") == []


class TestParseReturnLines:
    def test_valid_line(self):
        raw = 'SUMMARY_RETURN: {"code": "return -1", "line": 42, "conditions": ["buf == NULL"]}'
        returns = parse_return_lines(raw)
        assert len(returns) == 1
        assert returns[0].code == "return -1"
        assert returns[0].line == 42
        assert returns[0].conditions == ["buf == NULL"]

    def test_no_conditions(self):
        raw = 'SUMMARY_RETURN: {"code": "return 0", "line": 50, "conditions": []}'
        returns = parse_return_lines(raw)
        assert returns[0].conditions == []


class TestParseErrorLines:
    def test_valid_line(self):
        raw = 'SUMMARY_ERROR: {"code": "return NULL", "line": 10}'
        errors = parse_error_lines(raw)
        assert len(errors) == 1
        assert errors[0] == "return NULL"

    def test_multiple(self):
        raw = (
            'SUMMARY_ERROR: {"code": "return -1", "line": 5}\n'
            'SUMMARY_ERROR: {"code": "return ENOMEM", "line": 15}\n'
        )
        errors = parse_error_lines(raw)
        assert len(errors) == 2


class TestBuildSummary:
    def test_from_query_outputs(self):
        s = build_summary_from_query_outputs(
            "parse_header", "net/http.c",
            taint_output='SUMMARY_TAINT: {"source_param": "buf", "source_index": 0, "sink_call": "memcpy", "sink_arg_index": 0, "hop_count": 2}',
            guard_output='SUMMARY_GUARD: {"param": "len", "param_index": 1, "conditions": ["len > 0"]}',
            return_output='SUMMARY_RETURN: {"code": "return -1", "line": 30, "conditions": ["err"]}',
            error_output='SUMMARY_ERROR: {"code": "return -1", "line": 30}',
            callees=["net/util.c:validate_len"],
        )
        assert s.function == "parse_header"
        assert s.file == "net/http.c"
        assert len(s.taint_rules) == 1
        assert len(s.preconditions) == 1
        assert len(s.returns) == 1
        assert len(s.error_paths) == 1
        assert s.callees == ["net/util.c:validate_len"]
        assert s.evidence_tier == EvidenceTier.XREF_BACKED

    def test_empty_outputs(self):
        s = build_summary_from_query_outputs("f", "a.c")
        assert s.is_empty()
        assert s.taint_rules == []


class TestFunctionSummary:
    def test_is_empty(self):
        s = FunctionSummary(function="f", file="a.c")
        assert s.is_empty()
        s.taint_rules.append(TaintRule("x", 0, "y", 0))
        assert not s.is_empty()

    def test_format_oneline_empty(self):
        s = FunctionSummary(function="log_msg", file="a.c")
        result = s.format_for_context("oneline")
        assert "log_msg" in result
        assert "no CPG" in result

    def test_format_oneline_with_taint(self):
        s = FunctionSummary(function="parse", file="a.c")
        s.taint_rules.append(TaintRule("buf", 0, "memcpy", 0))
        result = s.format_for_context("oneline")
        assert "taint→memcpy" in result

    def test_format_full_empty_returns_empty(self):
        s = FunctionSummary(function="f", file="a.c")
        assert s.format_for_context("full") == ""

    def test_format_full_with_data(self):
        s = FunctionSummary(function="parse", file="a.c")
        s.taint_rules.append(TaintRule("buf", 0, "memcpy", 1, hop_count=3))
        s.preconditions.append(Precondition("len", 1, ["len > 0"]))
        s.returns.append(ReturnCondition("return -1", 30, ["err"]))
        s.error_paths.append("return NULL")

        result = s.format_for_context("full")
        assert "### CPG summary" in result
        assert "Taint propagation" in result
        assert "memcpy" in result
        assert "3 hops" in result
        assert "Guards" in result
        assert "len > 0" in result
        assert "Returns" in result
        assert "Error returns" in result
        assert "xref_backed" in result

    def test_to_dict(self):
        s = FunctionSummary(function="f", file="a.c")
        s.taint_rules.append(TaintRule("x", 0, "y", 1))
        d = s.to_dict()
        assert d["function"] == "f"
        assert d["file"] == "a.c"
        assert len(d["taint_rules"]) == 1
        assert d["taint_rules"][0]["sink_call"] == "y"
        assert d["evidence_tier"] == "xref_backed"

    def test_to_dict_roundtrip_fields(self):
        s = FunctionSummary(
            function="f", file="a.c",
            callees=["b.c:g"], callers=["c.c:h"],
        )
        d = s.to_dict()
        assert d["callees"] == ["b.c:g"]
        assert d["callers"] == ["c.c:h"]


class TestPropagateTaintUpward:
    def test_inherits_callee_taint(self):
        callee = FunctionSummary(function="sink_wrapper", file="lib.c")
        callee.taint_rules.append(TaintRule(
            source_param="data", source_index=0,
            sink_call="memcpy", sink_arg_index=1, hop_count=1,
        ))

        caller = FunctionSummary(function="handler", file="main.c")
        call_args = [{"callee_index": 0, "caller_param": "input"}]

        inherited = propagate_taint_upward(callee, caller, call_args)
        assert len(inherited) == 1
        assert inherited[0].source_param == "input"
        assert inherited[0].sink_call == "memcpy"
        assert inherited[0].hop_count == 2
        assert len(caller.taint_rules) == 1

    def test_no_duplicate_propagation(self):
        callee = FunctionSummary(function="f", file="a.c")
        callee.taint_rules.append(TaintRule("x", 0, "memcpy", 1))

        caller = FunctionSummary(function="g", file="b.c")
        caller.taint_rules.append(TaintRule(
            source_param="buf", source_index=-1,
            sink_call="memcpy", sink_arg_index=1, hop_count=2,
        ))
        call_args = [{"callee_index": 0, "caller_param": "buf"}]

        inherited = propagate_taint_upward(callee, caller, call_args)
        assert len(inherited) == 0
        assert len(caller.taint_rules) == 1

    def test_empty_on_no_rules(self):
        callee = FunctionSummary(function="f", file="a.c")
        caller = FunctionSummary(function="g", file="b.c")
        inherited = propagate_taint_upward(callee, caller, [])
        assert inherited == []


class TestResolveSccSummaries:
    def test_propagates_within_scc(self):
        summaries = {
            "a.c:f": FunctionSummary(function="f", file="a.c"),
            "a.c:g": FunctionSummary(function="g", file="a.c"),
        }
        summaries["a.c:g"].taint_rules.append(TaintRule(
            source_param="buf", source_index=0,
            sink_call="write", sink_arg_index=1, hop_count=1,
        ))

        call_edges = [
            {"caller_file": "a.c", "caller": "f", "callee": "g",
             "args": [{"callee_index": 0, "caller_param": "data"}]},
        ]

        new_rules = resolve_scc_summaries(
            ["a.c:f", "a.c:g"], summaries, call_edges,
        )
        assert new_rules >= 1
        assert len(summaries["a.c:f"].taint_rules) == 1
        assert summaries["a.c:f"].taint_rules[0].source_param == "data"

    def test_converges_without_changes(self):
        summaries = {
            "a.c:f": FunctionSummary(function="f", file="a.c"),
            "a.c:g": FunctionSummary(function="g", file="a.c"),
        }
        call_edges = [
            {"caller_file": "a.c", "caller": "f", "callee": "g", "args": []},
        ]
        new_rules = resolve_scc_summaries(
            ["a.c:f", "a.c:g"], summaries, call_edges,
        )
        assert new_rules == 0
