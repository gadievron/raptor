"""Overflow queries require one matching source operation, not two mentions."""

import pytest

from core.audit import arithmetic_operation as operation, sweep


@pytest.fixture
def c_grammar():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


@pytest.mark.parametrize("expression,operator,operands", [
    pytest.param("a + b", "+", ["a", "b"], id="sum"),
    pytest.param("b + a", "+", ["a", "b"], id="reversed-sum"),
    pytest.param("a * b", "*", ["a", "b"], id="product"),
    pytest.param("b * a", "*", ["a", "b"], id="reversed-product"),
    pytest.param("a - b", "-", ["a", "b"], id="difference"),
    pytest.param("(a) + ((b))", "+", ["a", "b"], id="parentheses"),
    pytest.param("a /* comment */ * b", "*", ["a", "b"], id="inline-comment"),
    pytest.param("a + a", "+", ["a", "a"], id="same-value-twice"),
])
def test_one_matching_operation_binds(c_grammar, expression, operator, operands):
    source = f"unsigned Read(unsigned a, unsigned b) {{\n    return {expression};\n}}"
    result = operation.bind_arithmetic_operation(source, operands, operator, language="c")
    assert result.status == "bound"
    assert result.line == 2
    assert result.column == 12


@pytest.mark.parametrize("body,operator,status", [
    pytest.param("return a + b;", "*", "unbound", id="wrong-operator"),
    pytest.param("return b - a;", "-", "unbound", id="reversed-subtraction"),
    pytest.param("unsigned x = a + 1; return b + 1;", "+", "unbound", id="separate-expressions"),
    pytest.param("return a * b;", "+", "unbound", id="product-is-not-sum"),
    pytest.param("return obj.a + b;", "+", "unbound", id="field-is-not-variable"),
    pytest.param("return obj->a + b;", "+", "unbound", id="pointer-field-is-not-variable"),
    pytest.param("return a[0] + b;", "+", "unbound", id="subscript-is-not-variable"),
    pytest.param("return *a + b;", "+", "unbound", id="dereference-is-not-variable"),
    pytest.param("return (unsigned)a + b;", "+", "unbound", id="cast-changes-model"),
    pytest.param("return f(a) + b;", "+", "unbound", id="call-is-not-variable"),
    pytest.param("return a++ + b;", "+", "unbound", id="mutation-is-not-variable"),
    pytest.param("return (a + 1) + b;", "+", "unbound", id="compound-operand"),
    pytest.param('const char *s = "a + b"; return 0;', "+", "unbound", id="string-only"),
    pytest.param("/* a + b */ return 0;", "+", "unbound", id="comment-only"),
    pytest.param("return sizeof(a + b);", "+", "unbound", id="unevaluated-sizeof"),
    pytest.param("return _Generic(a + b, unsigned: 1, default: 0);", "+", "unavailable", id="generic-selection"),
    pytest.param("{ enum { a = 1, b = 2, value = a + b }; } return 0;", "+", "unbound", id="enum-constant"),
    pytest.param("return _Alignof(a + b);", "+", "unavailable", id="invalid-alignof-expression"),
    pytest.param("if (a < 10) return a + b; return a + b;", "+", "ambiguous", id="two-occurrences"),
    pytest.param("unsigned x = a + b; return b + a;", "+", "ambiguous", id="reversed-duplicate"),
    pytest.param("\n#if ACTIVE\nreturn a + b;\n#endif\nreturn 0;", "+", "unavailable", id="conditional-compilation"),
])
def test_nonmatching_or_ambiguous_operations_decline(c_grammar, body, operator, status):
    source = f"unsigned Read(unsigned a, unsigned b) {{ {body} }}"
    result = operation.bind_arithmetic_operation(source, ["a", "b"], operator, language="c")
    assert result.status == status


@pytest.mark.parametrize("language", [None, "go", "rust", "python"])
def test_unsupported_language_cannot_fall_back_to_text(language):
    result = operation.bind_arithmetic_operation("a + b", ["a", "b"], "+", language=language)
    assert result.status == "unavailable"


@pytest.mark.parametrize("parser_failure", [False, True], ids=["missing-parser", "parser-error"])
def test_parser_unavailability_declines_without_lexical_fallback(monkeypatch, parser_failure):
    def unavailable(language):
        if parser_failure:
            raise RuntimeError("test parser failure")
        return None

    monkeypatch.setattr(operation, "_get_parser", unavailable)
    result = operation.bind_arithmetic_operation("a + b", ["a", "b"], "+", language="c")
    assert result.status == "unavailable"


def test_malformed_source_does_not_earn_operation_identity(c_grammar):
    assert operation.bind_arithmetic_operation("int Read( { a + b", ["a", "b"], "+", language="c").status == "unavailable"


@pytest.mark.parametrize("expression,operator,expected", [
    pytest.param("a + b", "+", "bound", id="cpp-sum"),
    pytest.param("noexcept(a + b)", "+", "unbound", id="cpp-noexcept"),
    pytest.param("alignof(decltype(a + b))", "+", "unbound", id="cpp-alignof"),
    pytest.param("sizeof(decltype(a + b))", "+", "unbound", id="cpp-decltype"),
])
def test_cpp_operation_identity(expression, operator, expected):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    result = operation.bind_arithmetic_operation(
        f"unsigned Read(unsigned a, unsigned b) {{ return {expression}; }}",
        ["a", "b"], operator, language="cpp",
    )
    assert result.status == expected


@pytest.mark.parametrize("body,hypothesis", [
    pytest.param("unsigned x = a + 1; return b + 1;", "integer overflow in `a` + `b`", id="separate-operations"),
    pytest.param("return a + b;", "integer overflow in `a` * `b`", id="invented-product"),
    pytest.param("return a * b;", "integer overflow in `a` + `b`", id="invented-sum"),
    pytest.param("return b - a;", "integer underflow in `a` - `b`", id="reversed-difference"),
    pytest.param("return sizeof(a + b);", "integer overflow in `a` + `b`", id="sizeof-only"),
    pytest.param("unsigned x = a + b; return a + b;", "integer overflow in `a` + `b`", id="ambiguous-operation"),
])
def test_unbound_queries_stop_before_premise_or_solver_work(c_grammar, monkeypatch, body, hypothesis):
    from packages.exploit_feasibility import smt_verbs

    def forbidden(*args, **kwargs):
        pytest.fail("unbound operation should stop before premises or solver")

    monkeypatch.setattr(sweep, "_extract_comparison_premises", forbidden)
    monkeypatch.setattr(smt_verbs, "check_overflow", forbidden)
    source = f"unsigned Read(unsigned a, unsigned b) {{ if (a <= 10 && b <= 10) {{ {body} }} return 0; }}"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read",
                                     verb="check-overflow", source=source, hypothesis=hypothesis)
    assert result.outcome == "inconclusive"
    assert not result.errors
    assert result.details["arithmetic_operation_status"] in {"unbound", "ambiguous"}


@pytest.mark.parametrize("expression,hypothesis", [
    pytest.param("a + b", "integer overflow in `a` + `b`", id="bound-sum"),
    pytest.param("b * a", "integer overflow in `a` * `b`", id="commutative-product"),
])
def test_bound_query_reaches_the_real_solver(c_grammar, expression, hypothesis):
    pytest.importorskip("z3")
    source = f"unsigned Read(unsigned a, unsigned b) {{ if (a <= 10 && b <= 10) return {expression}; return 0; }}"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read",
                                     verb="check-overflow", source=source, hypothesis=hypothesis)
    assert result.outcome == "refuted"
    assert result.details["source_operation"]["line"] == 1
    assert result.details["source_operation"]["column"] > 1
    assert not result.errors


def test_cpp_default_argument_does_not_bind_to_the_callee_body():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    source = "unsigned a, b; unsigned Read(unsigned value = a + b) { return value; }"
    result = operation.bind_arithmetic_operation(source, ["a", "b"], "+", language="cpp")
    assert result.status == "unbound"


def test_cpp_nested_callback_does_not_supply_the_outer_operation():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    source = "unsigned Read(unsigned a, unsigned b) { auto cb = [&](){return a + b;}; return 0; }"
    result = operation.bind_arithmetic_operation(source, ["a", "b"], "+", language="cpp")
    assert result.status == "unbound"


def test_unevaluated_occurrence_does_not_make_a_real_operation_ambiguous(c_grammar):
    source = "unsigned Read(unsigned a, unsigned b) { unsigned width = sizeof(a + b); return a + b; }"
    result = operation.bind_arithmetic_operation(source, ["a", "b"], "+", language="c")
    assert result.status == "bound"


@pytest.mark.parametrize("outcome", ["confirmed", "refuted"])
def test_same_source_worker_from_before_operation_binding_is_rejected(c_grammar, monkeypatch, outcome):
    from dataclasses import asdict
    from core.audit.probe_function_scope import source_binding, source_for_function

    source = "unsigned Read(unsigned a, unsigned b) { if (a <= 10 && b <= 10) return a + b; return 0; }"
    _, selected = source_for_function(source, "record.c", "Read")
    old_binding = source_binding(selected, "Read", verb="check-overflow")
    del old_binding["query_contract"]
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read",
                            rule_id="smt:check-overflow", outcome=outcome,
                            details={"source_scope": old_binding}, matches=[{"model": {}}])
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c", function_name="Read", verb="check-overflow", source=source,
        hypothesis="integer overflow in `a` + `b`",
    )
    assert result.outcome == "inconclusive"
    assert not result.matches
    assert result.details["source_scope_status"] == "unbound-worker-result"


@pytest.mark.parametrize("body", [
    pytest.param("unsigned width = sizeof(int[a + b]); return a + b;", id="vla-extent-may-execute"),
    pytest.param("unsigned x = _Generic(a, unsigned: a + b, default: 0); return a + b;", id="generic-arm-may-execute"),
    pytest.param("\n#if ACTIVE\nunsigned x = a + b;\n#endif\nreturn a + b;", id="preprocessor-arm-may-execute"),
])
def test_unknown_evaluation_cannot_hide_a_second_occurrence(c_grammar, body):
    source = f"unsigned Read(unsigned a, unsigned b) {{ {body} }}"
    assert operation.bind_arithmetic_operation(source, ["a", "b"], "+", language="c").status == "unavailable"


def test_cpp_compile_time_condition_does_not_bind_runtime_arithmetic():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    source = "unsigned Read(unsigned a, unsigned b) { if constexpr (a + b > 0) return 1; return 0; }"
    assert operation.bind_arithmetic_operation(source, ["a", "b"], "+", language="cpp").status == "unavailable"
