"""A source operation and its predicates must share a justified integer frame."""

from dataclasses import asdict

import pytest

from core.audit import arithmetic_operation as operation, sweep
from core.audit.arithmetic_types import integer_type
from core.audit.probe_function_scope import source_binding, source_for_function

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.fixture
def c_grammar():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


def bind(left, right, expression="a + b", body=None):
    text = f"int Read({left} a, {right} b) {{ {body or ('if (a <= 10 && b <= 10) return ' + expression + '; return 0;')} }}"
    op = "*" if "*" in expression else "-" if "-" in expression else "+"
    return operation.bind_arithmetic_operation(text, ["a", "b"], op, language="c", integer_abi="ilp32")


@pytest.mark.parametrize("spelling,width,signed,profile", [
    pytest.param("int", 32, True, "int32", id="signed-int"),
    pytest.param("signed int", 32, True, "int32", id="explicit-signed-int"),
    pytest.param("unsigned int", 32, False, "uint32", id="unsigned-int"),
    pytest.param("unsigned", 32, False, "uint32", id="unsigned-shorthand"),
    pytest.param("signed char", 8, True, "int32", id="signed-char-promotion"),
    pytest.param("unsigned char", 8, False, "int32", id="unsigned-char-promotion"),
    pytest.param("short", 16, True, "int32", id="short-promotion"),
    pytest.param("short int", 16, True, "int32", id="short-int-promotion"),
    pytest.param("unsigned short", 16, False, "int32", id="unsigned-short-promotion"),
    pytest.param("short unsigned int", 16, False, "int32", id="reordered-specifiers"),
    pytest.param("_Bool", 1, False, "int32", id="c-boolean-promotion"),
    pytest.param("bool", 1, False, "int32", id="cpp-boolean-promotion"),
])
def test_builtin_grammar_and_c32_promotions(spelling, width, signed, profile):
    kind = integer_type(spelling, integer_abi="ilp32")
    assert kind is not None
    assert (kind.width, kind.signed, kind.profile) == (width, signed, profile)


@pytest.mark.parametrize("spelling", [
    "char", "size_t", "uint32_t", "uint64_t",
    "counter_t", "float", "double", "signed unsigned int", "unsigned char int",
])
def test_unknown_or_abi_dependent_spelling_is_not_guessed(spelling):
    assert integer_type(spelling, integer_abi="ilp32") is None


@pytest.mark.parametrize("left,right,profile", [
    pytest.param("unsigned", "unsigned int", "uint32", id="matching-unsigned"),
    pytest.param("signed int", "int", "int32", id="matching-signed"),
    pytest.param("unsigned char", "unsigned short", "int32", id="different-storage-same-promotion"),
    pytest.param("signed char", "int", "int32", id="narrow-and-int"),
])
def test_declared_types_select_the_common_promoted_frame(c_grammar, left, right, profile):
    result = bind(left, right)
    assert result.status == "bound"
    assert result.type_status == "bound"
    assert result.profile == profile
    assert result.kind == ("unsigned_wrap" if profile == "uint32" else "signed_wrap")
    assert dict(result.types) == {"a": left, "b": right}


@pytest.mark.parametrize("left,right", [
    pytest.param("int", "unsigned", id="mixed-signedness"),
    pytest.param("unsigned short", "unsigned", id="promotion-mixes-profiles"),
    pytest.param("clock_t", "clock_t", id="opaque-type"),
    pytest.param("uint64_t", "uint64_t", id="unresolved-typedef"),
    pytest.param("volatile unsigned", "unsigned", id="volatile-value"),
    pytest.param("_Atomic(unsigned)", "unsigned", id="atomic-value"),
])
def test_unsupported_type_context_declines(c_grammar, left, right):
    result = bind(left, right)
    assert result.type_status == "unavailable"


def test_promoted_values_retain_their_source_storage_ranges(c_grammar):
    result = bind("signed char", "unsigned short")
    assert result.domains == ("a >= (0 - 128)", "a <= 127", "b >= 0", "b <= 65535")


@pytest.mark.parametrize("text,expected", [
    pytest.param("unsigned Read(unsigned *a, unsigned b) { if (b <= 10) return a + b; return 0; }", "unavailable", id="pointer"),
    pytest.param("unsigned Read(unsigned a, unsigned b) { { long a = 0; if (a <= 10 && b <= 10) return a + b; } return 0; }", "unavailable", id="inner-shadow"),
    pytest.param("unsigned Read(unsigned a) { if (a <= limit) return a + missing; return 0; }", "unavailable", id="unknown-operand-and-bound"),
    pytest.param("unsigned Read(unsigned a, unsigned b) { if (a <= limit && b <= 10) return a + b; return 0; }", "unavailable", id="unknown-guard-name"),
    pytest.param("unsigned Read(unsigned a, unsigned b) { if (a <= 10 && b <= 10) return a + b; unsigned limit = 1; }", "bound", id="later-unrelated-declaration"),
])
def test_bindings_come_from_the_operation_scope(c_grammar, text, expected):
    result = operation.bind_arithmetic_operation(text, ["a", "b"], "+", language="c", integer_abi="ilp32")
    assert result.type_status == expected


@pytest.mark.parametrize("expression,hypothesis,expected", [
    pytest.param("a * b", "integer overflow in `a` * `b`", "confirmed", id="promoted-product-can-overflow"),
    pytest.param("a + b", "integer overflow in `a` + `b`", "refuted", id="promoted-sum-fits"),
])
def test_real_solver_respects_unsigned_short_promotion(c_grammar, expression, hypothesis, expected):
    pytest.importorskip("z3")
    text = f"int Read(unsigned short a, unsigned short b) {{ if (a <= 65535 && b <= 65535) return {expression}; return 0; }}"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=text, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == expected, result.errors
    info = result.details["source_operation"]
    assert info["profile"] == "int32" and info["kind"] == "signed_wrap"
    assert info["domains"] == ["a >= 0", "a <= 65535", "b >= 0", "b <= 65535"]


def test_explicit_math_api_shows_why_uint32_was_the_wrong_product_frame():
    pytest.importorskip("z3")
    from packages.exploit_feasibility.smt_verbs import check_overflow

    result = check_overflow(["a", "b"], "*", profile="uint32", guards=["a <= 65535", "b <= 65535"])
    assert result["feasible"] is False


@pytest.mark.parametrize("ctype", ["signed char", "unsigned char"])
def test_narrow_storage_does_not_allow_arbitrary_promoted_int_values(c_grammar, ctype):
    pytest.importorskip("z3")
    # Addition distinguishes narrow storage domains from unrestricted int
    # inputs without making this domain check depend on nonlinear solving.
    text = f"int Read({ctype} a, {ctype} b) {{ return a + b; }}"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=text, hypothesis="integer overflow in `a` + `b`", integer_abi="ilp32")
    assert result.outcome == "refuted", result.errors
    assert result.details["source_operation"]["profile"] == "int32"


@pytest.mark.parametrize("ctype", ["size_t", "uintptr_t", "uint64_t"])
def test_unknown_width_stops_before_solver(c_grammar, monkeypatch, ctype):
    from packages.exploit_feasibility import smt_verbs

    def forbidden(*args, **kwargs):
        pytest.fail("unknown types must stop before solver admission")

    monkeypatch.setattr(sweep, "_premise_gate", forbidden)
    monkeypatch.setattr(smt_verbs, "check_overflow", forbidden)
    text = f"int Read({ctype} a, {ctype} b) {{ if (a <= 10 && b <= 10) return a + b; return 0; }}"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=text, hypothesis="integer overflow in `a` + `b`", integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert result.details["arithmetic_type_status"] == "unavailable"


@pytest.mark.parametrize("outcome", ["confirmed", "refuted"])
def test_old_guard_only_worker_cannot_bypass_source_type_admission(c_grammar, monkeypatch, outcome):
    text = "unsigned Read(unsigned a, unsigned b) { if (a <= 10 && b <= 10) return a + b; return 0; }"
    _, selected = source_for_function(text, "record.c", "Read")
    binding = source_binding(selected, "Read", verb="check-overflow", integer_abi="ilp32", hypothesis="integer overflow in `a` + `b`")
    binding["query_contract"] = "dominating-overflow-guards-v2"
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", outcome=outcome,
                            rule_id="smt:check-overflow", details={"source_scope": binding}, matches=[{}])
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-overflow",
                                         source=text, hypothesis="integer overflow in `a` + `b`", integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert not result.matches
    assert result.details["source_scope_status"] == "unbound-worker-result"


def test_signed_premises_and_main_query_use_the_same_profile(c_grammar):
    pytest.importorskip("z3")
    text = "int Read(int a, int b) { if (a < 0 && b == 0) return a + b; return 0; }"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=text, hypothesis="integer overflow in `a` + `b`", integer_abi="ilp32")
    assert result.outcome == "refuted", result.errors
    assert result.details["source_operation"]["profile"] == "int32"


@pytest.mark.parametrize("hint,expected", [
    pytest.param(None, False, id="source-only"),
    pytest.param("unsigned short", False, id="matching-hint"),
    pytest.param("short unsigned int", False, id="equivalent-hint"),
    pytest.param("unsigned int", None, id="wrong-storage-width"),
    pytest.param("short", None, id="wrong-signedness"),
])
def test_auxiliary_disproof_uses_source_types_not_hint_overrides(c_grammar, hint, expected):
    pytest.importorskip("z3")
    from core.audit.condition_smt import disprove_integer_overflow

    text = "int Read(unsigned short a, unsigned short b) { if (a <= 65535 && b <= 65535) return a * b; return 0; }"
    result = disprove_integer_overflow("integer overflow in `a * b`", text,
                                      var_types={"a": hint} if hint is not None else None,
                                      file_path="record.c", function_name="Read", integer_abi="ilp32")
    assert result.disproved is expected, result.reasoning
    assert not result.error


@pytest.mark.parametrize("text", [
    pytest.param("unsigned Read(unsigned a, unsigned b, int limit) { if (a <= limit && b <= 10) return a + b; return 0; }", id="mixed-guard-profile"),
    pytest.param("int Read(int a, int b) { if (a <= 2147483648 && b <= 10) return a + b; return 0; }", id="wide-guard-literal"),
    pytest.param("unsigned Read(unsigned a, unsigned b) { if (a <= 10 && b <= limit) return a + b; unsigned limit = 1; }", id="later-bound-declaration"),
    pytest.param("unsigned Read(unsigned a, unsigned b) { { unsigned limit = 1; } if (a <= limit && b <= 10) return a + b; return 0; }", id="sibling-bound-declaration"),
])
def test_every_guard_value_needs_a_compatible_visible_type(c_grammar, text):
    result = operation.bind_arithmetic_operation(text, ["a", "b"], "+", language="c", integer_abi="ilp32")
    assert result.status == "bound"
    assert result.guard_status in {"bound", "unavailable"}
    assert result.type_status == "unavailable"


def test_const_qualifier_preserves_builtin_value_type(c_grammar):
    result = bind("const unsigned int", "unsigned")
    assert result.type_status == "bound" and result.profile == "uint32"


@pytest.mark.parametrize("declarations", [
    pytest.param("unsigned &a, unsigned b", id="reference-value"),
    pytest.param("Counter a, Counter b", id="overloaded-user-type"),
])
def test_cpp_non_builtin_arithmetic_is_not_a_bitvector_query(declarations):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_cpp")
    text = f"unsigned Read({declarations}) {{ if (a <= 10 && b <= 10) return a + b; return 0; }}"
    result = operation.bind_arithmetic_operation(text, ["a", "b"], "+", language="cpp", integer_abi="ilp32")
    assert result.type_status == "unavailable"


def test_typedef_spelling_cannot_impersonate_a_fixed_width_builtin(c_grammar):
    text = "typedef unsigned char uint32_t; int Read(uint32_t a, uint32_t b) { if (a <= 10 && b <= 10) return a + b; return 0; }"
    result = operation.bind_arithmetic_operation(text, ["a", "b"], "+", language="c", integer_abi="ilp32")
    assert result.status == "bound" and result.type_status == "unavailable"


def test_signed_subtraction_uses_the_signed_backend_oracle(c_grammar):
    result = bind("int", "int", expression="a - b")
    assert result.status == "bound" and result.guard_status == "bound"
    assert result.type_status == "bound" and result.kind == "signed_wrap"


@pytest.mark.parametrize('declaration', [
    pytest.param('unsigned a __attribute__((vector_size(16)))', id='vector-width-after-name'),
    pytest.param('unsigned __attribute__((mode(DI))) a', id='integer-mode-before-name'),
    pytest.param('unsigned a __attribute__((mode(DI)))', id='integer-mode-after-name'),
    pytest.param('unsigned a __attribute__((aligned(16)))', id='unmodeled-alignment-attribute'),
])
def test_parameter_attributes_cannot_masquerade_as_plain_scalar_types(c_grammar, declaration):
    text = f'unsigned Read({declaration},unsigned b){{return a+b;}}'
    result = operation.bind_arithmetic_operation(text, ['a', 'b'], '+', language='c', integer_abi='ilp32')
    assert result.status == 'unavailable' and result.type_status == 'unavailable'
