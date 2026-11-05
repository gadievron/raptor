"""Source-derived arithmetic probes cannot borrow another callable's input."""

from dataclasses import asdict

import pytest

from core.audit import sweep
from core.audit.probe_function_scope import source_binding, source_for_function

VERBS = ("check-overflow", "check-oob", "check-overflow-to-oob", "check-negative-bypass")
SOURCE = "int Neighbor(void) { return 37; }\nint Read(void) { return 0; }\n"


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("function,found", [("Read", False), ("Neighbor", True)])
def test_arithmetic_dispatch_binds_only_the_requested_function(monkeypatch, verb, function, found):
    seen = []

    def observe(**request):
        seen.append(request["source"])
        return sweep.SweepResult(
            tool="smt", file_path=request["file_path"], function_name=request["function_name"],
            rule_id=f"smt:{request['verb']}", outcome="confirmed",
            details={"test_observation": True},
        )

    monkeypatch.setattr(sweep, "_run_smt_verb_on_source", observe)
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name=function,
                                     verb=verb, source=SOURCE, hypothesis="claim", integer_abi="ilp32")
    assert result.outcome == "confirmed"
    assert len(seen) == 1
    assert ("37" in seen[0]) is found
    assert result.details["source_scope"] == source_binding(seen[0], function, verb=verb, integer_abi="ilp32", hypothesis="claim")
    assert result.details["test_observation"] is True


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("name", ["Missing", ""])
def test_unresolved_function_does_not_dispatch_arithmetic(monkeypatch, verb, name):
    def forbidden(*args, **kwargs):
        pytest.fail("unresolved source should not dispatch a solver")

    monkeypatch.setattr(sweep, "_run_smt_verb_on_source", forbidden)
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", forbidden)
    request = dict(file_path="record.c", function_name=name, verb=verb,
                   source=SOURCE, hypothesis="claim", integer_abi="ilp32")
    assert sweep._run_smt_verb_inner(**request).outcome == "inconclusive"
    assert sweep._smt_verb_in_subprocess(**request).outcome == "inconclusive"


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("changed", ["binding", "body", "function", "file", "verb", "rule", "tool"])
@pytest.mark.parametrize("outcome", ["confirmed", "refuted"])
def test_arithmetic_parent_rejects_unbound_or_misattributed_results(monkeypatch, verb, changed, outcome):
    _, selected = source_for_function(SOURCE, "record.c", "Read")
    binding = source_binding(selected, "Read", verb=verb, integer_abi="ilp32", hypothesis="claim")
    result = sweep.SweepResult(
        tool="smt", file_path="record.c", function_name="Read", rule_id=f"smt:{verb}",
        outcome=outcome, details={"source_scope": binding}, matches=[{"model": {}}],
    )
    if changed == "binding":
        result.details = {}
    elif changed == "body":
        binding["sha256"] = "stale"
    elif changed == "function":
        result.function_name = "Neighbor"
    elif changed == "file":
        result.file_path = "other.c"
    elif changed == "verb":
        binding["verb"] = "validate-path"
    elif changed == "rule":
        result.rule_id = "smt:validate-path"
    elif changed == "tool":
        result.tool = "other"
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(result))
    observed = sweep._smt_verb_in_subprocess(
        file_path="record.c", function_name="Read", verb=verb, source=SOURCE, hypothesis="claim",
        integer_abi="ilp32",
    )
    assert observed.outcome == "inconclusive"
    assert not observed.matches
    assert observed.details["source_scope_status"] == "unbound-worker-result"
    assert observed.rule_id == f"smt:{verb}"


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("outcome", ["confirmed", "refuted", "inconclusive", "error"])
def test_bound_current_worker_results_survive_parent_admission(monkeypatch, verb, outcome):
    _, selected = source_for_function(SOURCE, "record.c", "Read")
    result = sweep.SweepResult(
        tool="smt", file_path="record.c", function_name="Read", rule_id=f"smt:{verb}",
        outcome=outcome, details={"source_scope": source_binding(selected, "Read", verb=verb, integer_abi="ilp32", hypothesis="claim")},
    )
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(result))
    observed = sweep._smt_verb_in_subprocess(
        file_path="record.c", function_name="Read", verb=verb, source=SOURCE, hypothesis="claim",
        integer_abi="ilp32",
    )
    assert observed.outcome == outcome
    assert observed.details == result.details


@pytest.mark.parametrize("requested,expected", [("Read", "inconclusive"), ("Neighbor", "refuted")])
def test_real_solver_cannot_borrow_a_neighboring_comparison(requested, expected):
    pytest.importorskip("z3")
    source = (
        "unsigned Neighbor(unsigned a, unsigned b) {\n"
        "    if (a <= 10 && b <= 10) return a + b;\n"
        "    return 0;\n}\n"
        "unsigned Read(unsigned a, unsigned b) { return a + b; }\n"
    )
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name=requested,
                                     verb="check-overflow", source=source,
                                     hypothesis="integer overflow in `a` + `b`", integer_abi="ilp32")
    assert result.outcome == expected
    if requested == "Read":
        assert "no source-level guard premises" in result.details["summary"]


@pytest.mark.parametrize("verb", VERBS)
def test_nested_callable_does_not_supply_arithmetic_source(monkeypatch, verb):
    source = "int Read(void) { auto callback = [](){return 37;}; return 0; }"
    seen = []

    def observe(**request):
        seen.append(request["source"])
        return sweep.SweepResult(tool="smt", file_path="record.cpp", function_name="Read",
                                 rule_id=f"smt:{verb}", outcome="inconclusive")

    monkeypatch.setattr(sweep, "_run_smt_verb_on_source", observe)
    sweep._run_smt_verb_inner(file_path="record.cpp", function_name="Read", verb=verb,
                              source=source, hypothesis="claim", integer_abi="ilp32")
    assert len(seen) == 1
    assert "37" not in seen[0]


@pytest.mark.parametrize("verb,checker,hypothesis,source", [
    (
        "check-oob", "check_oob", "`idx` is used as an array index",
        "int Neighbor(unsigned idx, unsigned buflen) { if (idx < buflen) return 0; return 0; }\n"
        "int Read(unsigned idx) { return 0; }\n",
    ),
    (
        "check-negative-bypass", "check_negative_bypass", "negative `amount`",
        "int Neighbor(int max_items) { return max_items; }\n"
        "int Read(int amount) { return amount; }\n",
    ),
    (
        "check-overflow-to-oob", "check_overflow_to_oob", "overflow at index",
        "int Neighbor(unsigned count, unsigned index) { if (count < 10) return 0; return 0; }\n"
        "int Read(unsigned index) { return 0; }\n",
    ),
])
def test_neighbor_names_cannot_complete_missing_operands(monkeypatch, verb, checker, hypothesis, source):
    from packages.exploit_feasibility import smt_verbs

    def forbidden(*args, **kwargs):
        pytest.fail("neighbor-only operands should not reach a solver")

    monkeypatch.setattr(smt_verbs, checker, forbidden)
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb=verb,
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert not result.errors


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("path,source,status", [
    ("record.txt", SOURCE, "unavailable"),
    ("record.c", "int Read( {", "unavailable"),
    ("record.cpp", "namespace A { int Read(){return 0;} } namespace B { int Read(){return 0;} }", "ambiguous"),
])
def test_unresolvable_arithmetic_scope_stops_before_vocabulary_or_child(monkeypatch, verb, path, source, status):
    def forbidden(*args, **kwargs):
        pytest.fail("unresolved scope should stop before vocabulary or native dispatch")

    monkeypatch.setattr(sweep, "_verb_vocab", forbidden)
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", forbidden)
    request = dict(file_path=path, function_name="Read", verb=verb, source=source, hypothesis="claim", integer_abi="ilp32")
    for runner in (sweep._run_smt_verb_inner, sweep._smt_verb_in_subprocess):
        result = runner(**request)
        assert result.outcome == "inconclusive"
        assert result.details["source_scope_status"] == status
