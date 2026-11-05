"""Only supported, dominating predicates may constrain an overflow query."""

from dataclasses import asdict

import pytest

from core.audit import arithmetic_operation as operation, sweep
from core.audit.probe_function_scope import source_binding, source_for_function


@pytest.fixture
def c_grammar():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


def source(body):
    return f"unsigned Read(unsigned a, unsigned b, unsigned limit, unsigned flag, unsigned value) {{ {body} }}"


def bind(body, *, language="c"):
    return operation.bind_arithmetic_operation(source(body), ["a", "b"], "+", language=language, integer_abi="ilp32")


@pytest.mark.parametrize("body,expected", [
    pytest.param("if (a <= 10 && b <= 10) return a + b; return 0;", ("a <= 10", "b <= 10"), id="enclosing-conjunction"),
    pytest.param("if (a <= 10) { if (b <= 10) return a + b; } return 0;", ("a <= 10", "b <= 10"), id="nested-guards"),
    pytest.param("if (a > 10 || b > 10) return 0; return a + b;", ("a <= 10", "b <= 10"), id="early-return-disjunction"),
    pytest.param("if (a > 10) return 0; if (b > 10) return 0; return a + b;", ("a <= 10", "b <= 10"), id="two-early-returns"),
    pytest.param("if (!(a > 10 || b > 10)) return a + b; return 0;", ("a <= 10", "b <= 10"), id="negation-polarity"),
    pytest.param("if (a > 10 || b > 10) return 0; else return a + b;", ("a <= 10", "b <= 10"), id="else-polarity"),
    pytest.param("if (flag && a <= 10 && b <= 10) return a + b; return 0;", ("flag != 0", "a <= 10", "b <= 10"), id="boolean-name"),
    pytest.param("if (a > 10) { a = 20; return 0; } if (b > 10) return 0; return a + b;", ("a <= 10", "b <= 10"), id="exit-path-mutation-is-irrelevant"),
    pytest.param("if (a > 10 || b > 10) { /* exit */ return 0; /* trailing comment */ } return a + b;", ("a <= 10", "b <= 10"), id="comment-after-return"),
    pytest.param("if (a <= 10 && b <= 10) { unsigned total = a + b; return total; } return 0;", ("a <= 10", "b <= 10"), id="initializer-operation"),
])
def test_supported_paths_preserve_exact_predicates(c_grammar, body, expected):
    result = bind(body)
    assert result.status == "bound"
    assert result.guard_status == "bound"
    assert result.premises == expected


@pytest.mark.parametrize("body", [
    pytest.param("return a + b; if (a <= 10 && b <= 10) return 0;", id="later-comparison"),
    pytest.param("if (a <= 10 && b <= 10) {} return a + b;", id="reconverged-sibling-branch"),
    pytest.param("unsigned bounded = a <= 10 && b <= 10; return a + b;", id="comparison-as-data"),
    pytest.param("if (flag) {} return a + b;", id="unrelated-comparison"),
    pytest.param('const char *s = "a <= 10 && b <= 10"; return a + b;', id="string-only-bounds"),
])
def test_non_dominating_comparisons_supply_no_premises(c_grammar, body):
    result = bind(body)
    assert result.status == "bound"
    assert result.guard_status == "no-guards"
    assert not result.premises


@pytest.mark.parametrize("body", [
    pytest.param("if (a <= 10 || b <= 10) return a + b; return 0;", id="disjunction-is-not-conjunction"),
    pytest.param("if (a <= 10 && b <= 10) return 0; else return a + b;", id="negated-conjunction"),
    pytest.param("if (a > 10 && b > 10) return 0; return a + b;", id="early-return-requires-disjunction"),
    pytest.param("if (a > 10 || b > 10) return 0; a = value; return a + b;", id="operand-assignment"),
    pytest.param("if (a > 10 || b > 10) return 0; ++b; return a + b;", id="operand-update"),
    pytest.param("if (a > limit || b > limit) return 0; limit = 1; return a + b;", id="bound-name-assignment"),
    pytest.param("if (a > 10 || b > 10) return 0; change(); return a + b;", id="unmodeled-call"),
    pytest.param("if (a > 10 || b > 10) return 0; { unsigned a = value; return a + b; }", id="shadowed-operand"),
    pytest.param("if (a > 10 || b > 10) return 0; *p = value; return a + b;", id="possible-alias-write"),
    pytest.param("if (a > 10 || b > 10) return 0; return emit(a + b);", id="unmodeled-expression-order"),
    pytest.param("if (a > 10 || b > 10) return 0; return flag ? a + b : 0;", id="conditional-expression"),
    pytest.param("while (flag) { if (a <= 10 && b <= 10) return a + b; } return 0;", id="loop-context"),
    pytest.param("if (flag) goto use; if (a > 10 || b > 10) return 0; use: return a + b;", id="goto-bypasses-guards"),
    pytest.param("switch (flag) { case 0: if (a > 10 || b > 10) return 0; default: return a + b; }", id="switch-context"),
    pytest.param("if (check(a) && b <= 10) return a + b; return 0;", id="call-in-condition"),
    pytest.param("if (a <= 10u && b <= 10) return a + b; return 0;", id="literal-type-is-unmodeled"),
    pytest.param("if (a <= 010 && b <= 10) return a + b; return 0;", id="octal-is-not-decimal"),
    pytest.param("if (a > 10 || b > 10) return 0; if (flag) { if (value) return 0; } return a + b;", id="unmodeled-partial-exit"),
])
def test_unmodeled_context_declines_instead_of_guessing(c_grammar, body):
    result = bind(body)
    assert result.status == "bound"
    assert result.guard_status == "unavailable"
    assert not result.premises


@pytest.mark.parametrize("body,expected", [
    pytest.param("if (a <= 10 && b <= 10) return a + b; return 0;", "refuted", id="real-protected-operation"),
    pytest.param("if (a > 10 || b > 10) return 0; return a + b;", "refuted", id="real-early-return-guards"),
    pytest.param("if (a <= 10 || b <= 10) return a + b; return 0;", "inconclusive", id="real-or-not-flattened"),
    pytest.param("if (a <= 10 && b <= 10) {} return a + b;", "inconclusive", id="real-sibling-not-a-guard"),
    pytest.param("return a + b; if (a <= 10 && b <= 10) return 0;", "inconclusive", id="real-later-bounds-not-a-guard"),
    pytest.param("if (a > 10 || b > 10) return 0; a = value; return a + b;", "inconclusive", id="real-mutated-value"),
])
def test_real_solver_verdict_uses_only_credited_guards(c_grammar, body, expected):
    pytest.importorskip("z3")
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source(body), hypothesis="integer overflow in `a` + `b`", integer_abi="ilp32")
    assert result.outcome == expected
    assert not result.errors
    if expected == "refuted":
        assert result.details["source_operation"]["guards"] == ["a <= 10", "b <= 10"]


@pytest.mark.parametrize("body", [
    pytest.param("if (a <= 10 || b <= 10) return a + b; return 0;", id="unsupported-branch"),
    pytest.param("if (a > 10 || b > 10) return 0; a = value; return a + b;", id="invalidated-values"),
])
def test_unavailable_guard_context_stops_before_solver(c_grammar, monkeypatch, body):
    from packages.exploit_feasibility import smt_verbs

    def forbidden(*args, **kwargs):
        pytest.fail("unavailable guards should not dispatch solver work")

    monkeypatch.setattr(sweep, "_premise_gate", forbidden)
    monkeypatch.setattr(smt_verbs, "check_overflow", forbidden)
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source(body), hypothesis="integer overflow in `a` + `b`", integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert result.details["arithmetic_guard_status"] == "unavailable"


@pytest.mark.parametrize("outcome", ["confirmed", "refuted"])
def test_worker_with_old_guard_contract_cannot_supply_a_verdict(c_grammar, monkeypatch, outcome):
    text = source("if (a <= 10 && b <= 10) return a + b; return 0;")
    _, selected = source_for_function(text, "record.c", "Read")
    binding = source_binding(selected, "Read", verb="check-overflow", integer_abi="ilp32", hypothesis="integer overflow in `a` + `b`")
    binding["query_contract"] = "unique-binary-operation-v1"
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read",
                            rule_id="smt:check-overflow", outcome=outcome,
                            details={"source_scope": binding}, matches=[{"model": {}}])
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-overflow",
                                         source=text, hypothesis="integer overflow in `a` + `b`", integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert not result.matches
    assert result.details["source_scope_status"] == "unbound-worker-result"


def test_partial_encoding_of_guard_premises_is_not_usable():
    pytest.importorskip("z3")
    reason = sweep._premise_gate(["a <= 10", "b <= 0x100000000"], "uint32")
    assert reason is not None and "unencodable" in reason


@pytest.mark.parametrize("body", [
    pytest.param("if (a <= 10 && b <= 10 && f0 && f1 && f2 && f3 && f4 && f5 && f6) return a + b; return 0;", id="premise-cap"),
    pytest.param("if (" + "!" * 130 + "(a <= 10 && b <= 10)) return a + b; return 0;", id="condition-work-cap"),
    pytest.param("{" * 70 + "if (a <= 10 && b <= 10) return a + b;" + "}" * 70 + "return 0;", id="path-depth-cap"),
])
def test_budget_exhaustion_declines_instead_of_truncating(c_grammar, body):
    result = bind(body)
    assert result.status == "bound"
    assert result.guard_status == "unavailable"
    assert not result.premises


@pytest.mark.parametrize("body", [
    pytest.param("if (a <= 10 && b <= 10) return a + b; return 0;", id="cpp-enclosing"),
    pytest.param("if (a > 10 || b > 10) return 0; else return a + b;", id="cpp-else"),
])
def test_cpp_condition_wrapper_retains_polarity(body):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    result = bind(body, language="cpp")
    assert result.guard_status == "bound"
    assert result.premises == ("a <= 10", "b <= 10")


@pytest.mark.parametrize("body", [
    pytest.param("if (a > 10 || b > 10) return 0; alias = 20; return a + b;", id="reference-alias-write"),
    pytest.param("if (flag) throw 0; if (a <= 10 && b <= 10) return a + b; return 0;", id="unsupported-throw-flow"),
])
def test_cpp_aliases_and_unmodeled_exits_do_not_reuse_guard_values(body):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    text = f"unsigned Read(unsigned &a, unsigned b, unsigned &alias, unsigned flag) {{ {body} }}"
    result = operation.bind_arithmetic_operation(text, ["a", "b"], "+", language="cpp", integer_abi="ilp32")
    assert result.guard_status == "unavailable"
    assert not result.premises


def test_statement_expression_does_not_hide_an_inner_branch(c_grammar):
    result = bind("if (a > 10 || b > 10) return 0; return ({ if (flag) return 0; a + b; });")
    assert result.status == "bound"
    assert result.guard_status == "unavailable"
    assert not result.premises


@pytest.mark.parametrize("body,expected", [
    pytest.param("if (a <= 10 && b <= 10) return a + b; return 0;", True, id="disproof-protected"),
    pytest.param("if (a > 10 || b > 10) return 0; return a + b;", True, id="disproof-early-return"),
    pytest.param("if (a <= 10 || b <= 10) return a + b; return 0;", None, id="disproof-disjunction"),
    pytest.param("if (a <= 10 && b <= 10) {} return a + b;", None, id="disproof-sibling-bounds"),
    pytest.param("return a + b; if (a <= 10 && b <= 10) return 0;", None, id="disproof-later-bounds"),
    pytest.param("if (a > 10 || b > 10) return 0; a = value; return a + b;", None, id="disproof-mutated-value"),
])
def test_auxiliary_disproof_obeys_the_same_guard_boundary(c_grammar, body, expected):
    pytest.importorskip("z3")
    from core.audit.condition_smt import disprove_integer_overflow

    text = source(body).replace("unsigned", "unsigned int")
    result = disprove_integer_overflow("integer overflow in `a + b`", text,
                                      file_path="record.c", function_name="Read", integer_abi="ilp32")
    assert result.disproved is expected, result.reasoning
    assert not result.error


@pytest.mark.parametrize("name,expected", [("Read", None), ("Neighbor", True), ("Missing", None)])
def test_auxiliary_disproof_cannot_borrow_a_neighboring_function(c_grammar, name, expected):
    pytest.importorskip("z3")
    from core.audit.condition_smt import disprove_integer_overflow

    text = (
        "unsigned int Neighbor(unsigned int a, unsigned int b) { if (a <= 10 && b <= 10) return a + b; return 0; }\n"
        "unsigned int Read(unsigned int a, unsigned int b) { return a + b; }\n"
    )
    result = disprove_integer_overflow("integer overflow in `a + b`", text,
                                      file_path="record.c", function_name=name, integer_abi="ilp32")
    assert result.disproved is expected, result.reasoning
    assert not result.error


def test_auxiliary_disproof_preserves_literal_subtraction_order(c_grammar):
    pytest.importorskip("z3")
    from core.audit.condition_smt import disprove_integer_overflow

    text = "unsigned int Read(unsigned int a) { if (a <= 4) return 4 - a; return 0; }"
    result = disprove_integer_overflow("integer underflow in `4 - a`", text,
                                      file_path="record.c", function_name="Read", integer_abi="ilp32")
    assert result.disproved is True, result.reasoning
    assert not result.error


@pytest.mark.parametrize("literal", ["4", "0x10"])
def test_operation_identity_accepts_exact_canonical_literals(c_grammar, literal):
    text = f"unsigned int Read(unsigned int a) {{ if (a <= 10) return a + {literal}; return 0; }}"
    result = operation.bind_arithmetic_operation(text, ["a", literal], "+", language="c", integer_abi="ilp32")
    assert result.status == "bound"
    assert result.premises == ("a <= 10",)


def test_empty_named_scope_cannot_use_the_legacy_single_function_fallback(c_grammar):
    pytest.importorskip("z3")
    from core.audit.condition_smt import disprove_integer_overflow

    text = "unsigned int Read(unsigned int a, unsigned int b) { if (a <= 10 && b <= 10) return a + b; return 0; }"
    hypothesis = "integer overflow in `a + b`"
    assert disprove_integer_overflow(hypothesis, text, integer_abi="ilp32").disproved is True
    for kwargs in [dict(file_path="record.c"), dict(file_path="record.c", function_name="")]:
        result = disprove_integer_overflow(hypothesis, text, **kwargs, integer_abi="ilp32")
        assert result.disproved is None
        assert "function scope unavailable" in result.reasoning
