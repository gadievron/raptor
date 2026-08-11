"""Tests for core.audit.demand_explore."""

from __future__ import annotations

import json

from core.audit.demand_explore import (
    ExpandedContext,
    ExpansionBudget,
    FunctionProfile,
    JoernQuery,
    QueryType,
    TriageBucket,
    TriageResult,
    classify_function,
    format_triage_summary,
    get_token_budget,
    save_triage,
    triage_functions,
)


class TestQueryType:
    def test_values(self):
        assert QueryType.CALLERS.value == "callers"
        assert QueryType.TAINT_TO_SINKS.value == "taint_to_sinks"


class TestJoernQuery:
    def test_callers(self):
        q = JoernQuery(method_name="parse_header", query_type=QueryType.CALLERS)
        script = q.to_joern_script()
        assert "parse_header" in script
        assert "caller" in script

    def test_callees(self):
        q = JoernQuery(method_name="parse_header", query_type=QueryType.CALLEES)
        script = q.to_joern_script()
        assert "callee" in script

    def test_taint_to_sinks(self):
        q = JoernQuery(method_name="parse_header", query_type=QueryType.TAINT_TO_SINKS)
        script = q.to_joern_script()
        assert "reachableByFlows" in script
        assert "memcpy" in script

    def test_taint_from_sources(self):
        q = JoernQuery(method_name="process", query_type=QueryType.TAINT_FROM_SOURCES)
        script = q.to_joern_script()
        assert "recv" in script
        assert "reachableByFlows" in script

    def test_guards(self):
        q = JoernQuery(method_name="check_auth", query_type=QueryType.GUARDS)
        script = q.to_joern_script()
        assert "controlStructureType" in script
        assert "IF" in script

    def test_data_deps(self):
        q = JoernQuery(method_name="process", query_type=QueryType.DATA_DEPS)
        script = q.to_joern_script()
        assert "reachableBy" in script


class TestExpansionBudget:
    def test_initial(self):
        b = ExpansionBudget(max_expansions=10)
        assert b.remaining == 10
        assert not b.exhausted

    def test_expand_succeeds(self):
        b = ExpansionBudget(max_expansions=2)
        assert b.try_expand("func_a") is True
        assert b.remaining == 1

    def test_expand_deduplicates(self):
        b = ExpansionBudget(max_expansions=2)
        b.try_expand("func_a")
        assert b.try_expand("func_a") is True
        assert b.remaining == 1

    def test_expand_exhausted(self):
        b = ExpansionBudget(max_expansions=1)
        b.try_expand("func_a")
        assert b.try_expand("func_b") is False
        assert b.exhausted

    def test_summary(self):
        b = ExpansionBudget(max_expansions=10)
        b.try_expand("func_a")
        s = b.summary()
        assert "1/10" in s
        assert "9 remaining" in s


class TestExpandedContext:
    def test_format_minimal(self):
        ctx = ExpandedContext(function="parse", file="src/parse.c")
        output = ctx.format_for_prompt()
        assert "parse" in output
        assert "src/parse.c" in output

    def test_format_with_source(self):
        ctx = ExpandedContext(
            function="parse", file="src/parse.c",
            source="int parse(char *buf) { return 0; }",
        )
        output = ctx.format_for_prompt()
        assert "```" in output
        assert "int parse" in output

    def test_format_with_evidence(self):
        ctx = ExpandedContext(
            function="parse", file="src/parse.c",
            evidence=[
                {"source": "joern", "detail": "taint flow found"},
            ],
        )
        output = ctx.format_for_prompt()
        assert "[joern]" in output
        assert "taint flow" in output


class TestClassifyFunction:
    def test_skip_unreachable_absent(self):
        p = FunctionProfile(
            name="dead_code", file="a.c",
            on_reachable_path=False, binary_present=False,
        )
        assert classify_function(p) == TriageBucket.SKIP

    def test_skip_unreachable_not_entry(self):
        p = FunctionProfile(
            name="utility", file="a.c",
            on_reachable_path=False, is_entry_point=False,
        )
        assert classify_function(p) == TriageBucket.SKIP

    def test_deep_dive_entry_point(self):
        p = FunctionProfile(
            name="main", file="a.c",
            on_reachable_path=True, is_entry_point=True,
        )
        assert classify_function(p) == TriageBucket.DEEP_DIVE

    def test_deep_dive_sink(self):
        p = FunctionProfile(
            name="memcpy_wrapper", file="a.c",
            on_reachable_path=True, is_sink=True,
        )
        assert classify_function(p) == TriageBucket.DEEP_DIVE

    def test_deep_dive_trust_boundary(self):
        p = FunctionProfile(
            name="parse_request", file="a.c",
            on_reachable_path=True, is_trust_boundary=True,
        )
        assert classify_function(p) == TriageBucket.DEEP_DIVE

    def test_deep_dive_taint_complex(self):
        p = FunctionProfile(
            name="complex_parser", file="a.c",
            on_reachable_path=True,
            has_taint_exposure=True,
            cyclomatic_complexity=15,
        )
        assert classify_function(p) == TriageBucket.DEEP_DIVE

    def test_investigate_taint(self):
        p = FunctionProfile(
            name="process_data", file="a.c",
            on_reachable_path=True,
            has_taint_exposure=True,
            cyclomatic_complexity=5,
        )
        assert classify_function(p) == TriageBucket.INVESTIGATE

    def test_investigate_dangerous_callees(self):
        p = FunctionProfile(
            name="handler", file="a.c",
            on_reachable_path=True,
            has_dangerous_callees=True,
        )
        assert classify_function(p) == TriageBucket.INVESTIGATE

    def test_glance_simple_leaf(self):
        p = FunctionProfile(
            name="get_len", file="a.c",
            on_reachable_path=True,
            line_count=10,
            cyclomatic_complexity=2,
        )
        assert classify_function(p) == TriageBucket.GLANCE

    def test_investigate_moderate(self):
        p = FunctionProfile(
            name="transform", file="a.c",
            on_reachable_path=True,
            line_count=50,
            cyclomatic_complexity=5,
        )
        assert classify_function(p) == TriageBucket.INVESTIGATE


class TestTokenBudget:
    def test_skip_is_zero(self):
        assert get_token_budget(TriageBucket.SKIP) == 0

    def test_deep_dive_is_highest(self):
        assert get_token_budget(TriageBucket.DEEP_DIVE) > get_token_budget(TriageBucket.INVESTIGATE)

    def test_investigate_is_mid(self):
        assert get_token_budget(TriageBucket.INVESTIGATE) > get_token_budget(TriageBucket.GLANCE)


class TestTriageResult:
    def test_add_and_counts(self):
        r = TriageResult()
        r.add("a.c:f1", TriageBucket.SKIP)
        r.add("a.c:f2", TriageBucket.DEEP_DIVE)
        r.add("a.c:f3", TriageBucket.INVESTIGATE)

        counts = r.bucket_counts()
        assert counts[TriageBucket.SKIP] == 1
        assert counts[TriageBucket.DEEP_DIVE] == 1
        assert counts[TriageBucket.INVESTIGATE] == 1

    def test_functions_in(self):
        r = TriageResult()
        r.add("a.c:f1", TriageBucket.SKIP)
        r.add("a.c:f2", TriageBucket.SKIP)
        r.add("a.c:f3", TriageBucket.DEEP_DIVE)

        assert len(r.functions_in(TriageBucket.SKIP)) == 2
        assert len(r.functions_in(TriageBucket.DEEP_DIVE)) == 1

    def test_estimated_tokens(self):
        r = TriageResult()
        r.add("a.c:f1", TriageBucket.SKIP)
        r.add("a.c:f2", TriageBucket.DEEP_DIVE)
        expected = 0 + 22000
        assert r.estimated_tokens() == expected

    def test_to_dict(self):
        r = TriageResult()
        r.add("a.c:f1", TriageBucket.INVESTIGATE)
        d = r.to_dict()
        assert d["classifications"]["a.c:f1"] == "investigate"
        assert d["summary"]["investigate"] == 1


class TestTriageFunctions:
    def test_batch_classify(self):
        profiles = [
            FunctionProfile(name="main", file="a.c",
                            on_reachable_path=True, is_entry_point=True),
            FunctionProfile(name="dead", file="a.c",
                            on_reachable_path=False, binary_present=False),
            FunctionProfile(name="util", file="a.c",
                            on_reachable_path=True, line_count=5,
                            cyclomatic_complexity=1),
        ]
        result = triage_functions(profiles)
        assert result.classifications["a.c:main"] == TriageBucket.DEEP_DIVE
        assert result.classifications["a.c:dead"] == TriageBucket.SKIP
        assert result.classifications["a.c:util"] == TriageBucket.GLANCE


class TestSaveTriage:
    def test_save(self, tmp_path):
        r = TriageResult()
        r.add("a.c:f1", TriageBucket.INVESTIGATE)
        path = tmp_path / "triage.json"
        save_triage(r, path)

        data = json.loads(path.read_text())
        assert data["classifications"]["a.c:f1"] == "investigate"
        assert data["summary"]["investigate"] == 1


class TestFormatSummary:
    def test_empty(self):
        r = TriageResult()
        assert "no functions" in format_triage_summary(r)

    def test_with_functions(self):
        r = TriageResult()
        r.add("a.c:f1", TriageBucket.SKIP)
        r.add("a.c:f2", TriageBucket.DEEP_DIVE)
        r.add("a.c:f3", TriageBucket.INVESTIGATE)
        s = format_triage_summary(r)
        assert "3 functions" in s
        assert "skip:" in s
        assert "deep_dive:" in s
        assert "$" in s
