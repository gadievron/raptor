"""Complete source argument tuples, not unrelated per-operand bounds."""

import pytest

from core.audit.literal_call import check_literal_calls

ARRAY = "int Read(int Index, int Flag) { int Data[4]={0}; if(Flag == 1 && Index >= 0 && Index <= 4) return Data[Index]; return 0; }"
HYPOTHESIS = "out-of-bounds read at `Data[Index]`"


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip("tree_sitter_c")


def check(callee=ARRAY, wrapper="int Drive(void) { return Read(4, 1); }", verb="check-array-bounds", hypothesis=HYPOTHESIS, language="c", abi="ilp32"):
    source = callee + "\n" + wrapper + "\n"
    return check_literal_calls(source, "Read", verb, hypothesis, abi, [2], language)


@pytest.mark.parametrize("arguments,verdict", [
    pytest.param("4, 1", "violation", id="reaching-off-by-one"),
    pytest.param("4, 0", "guard-excluded", id="other-argument-blocks-read"),
    pytest.param("3, 1", "safe", id="last-valid-element"),
    pytest.param("-1, 1", "guard-excluded", id="negative-guard-blocks-read"),
    pytest.param("0x4, (1)", "violation", id="canonical-literal-and-parentheses"),
])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_complete_tuple_is_checked_against_every_callee_guard(arguments, verdict, language):
    if language == "cpp":
        pytest.importorskip("tree_sitter_cpp")
    result = check(wrapper=f"int Drive(void) {{ return Read({arguments}); }}", language=language)
    assert result["status"] == "checked", result
    assert len(result["calls"]) == 1
    call = result["calls"][0]
    assert call["verdict"] == verdict
    assert call["arguments"]["Flag"] in (0, 1)
    assert result["proof_scope"] == "caller-entry-source-model"
    assert "entry to the cited wrapper is assumed" in result["assumptions"]


def test_missing_lower_guard_can_be_violated_by_an_actual_negative_literal():
    result = check(callee=ARRAY.replace("Index >= 0 && ", ""), wrapper="int Drive(void) { return Read(-1, 1); }")
    assert result["calls"][0]["verdict"] == "violation"
    assert result["calls"][0]["witness_index"] == -1


@pytest.mark.parametrize("wrapper", [
    pytest.param("int Drive(void) { if(0) return Read(4, 1); return 0; }", id="dead-branch"),
    pytest.param("int Drive(int Flag) { return Read(4, Flag); }", id="symbolic-caller-argument"),
    pytest.param("int Drive(void) { int Flag=0; return Read(4, Flag); }", id="local-value-flow"),
    pytest.param("int Drive(void) { return Read(4, 1) + 0; }", id="embedded-call"),
    pytest.param("int Drive(void) { before(); return Read(4, 1); }", id="prior-call"),
    pytest.param("int Drive(void) { return Read(2+2, 1); }", id="compound-argument"),
    pytest.param("int Drive(void) { return Read(sizeof(int), 1); }", id="sizeof-not-guessed"),
    pytest.param("int Drive(void) { return Other(4, 1); }", id="wrong-callee"),
    pytest.param("int Drive(void) { return Read(4); }", id="wrong-arity"),
    pytest.param("int Drive(void) { return Read(4U, 1); }", id="literal-suffix"),
    pytest.param("int Drive(void) { return Read(04, 1); }", id="ambiguous-octal"),
    pytest.param("int Drive(void) { return Read(2147483648, 1); }", id="wide-literal-type"),
    pytest.param("consteval int Drive(void) { return Read(4, 1); }", id="immediate-function"),
])
def test_unsupported_callers_never_supply_a_violation(wrapper):
    result = check(wrapper=wrapper)
    assert not any(call["verdict"] == "violation" for call in result["calls"])


@pytest.mark.parametrize("source", [
    pytest.param("#define Read Other\n" + ARRAY + "\nint Drive(void) { return Read(4,1); }", id="preprocessor"),
    pytest.param(ARRAY + "\nint Read(char *Index) { return 0; }\nint Drive(void) { return Read(4,1); }", id="overload-ambiguity"),
    pytest.param(ARRAY + "\nint Read(int, int);\nint Drive(void) { return Read(4,1); }", id="unresolved-prototype-context"),
])
def test_full_translation_unit_binding_refuses_unmodeled_context(source):
    result = check_literal_calls(source, "Read", "check-array-bounds", HYPOTHESIS, "ilp32", [3])
    assert result["status"] == "unavailable"


@pytest.mark.parametrize("kind,arguments,verdict", [
    ("unsigned char", "256, 1", None), ("unsigned", "-1, 1", None),
    ("_Bool", "2, 1", None), ("unsigned char", "4, 1", "violation"),
])
def test_implicit_argument_conversions_are_not_silently_guessed(kind, arguments, verdict):
    callee = ARRAY.replace("int Index", kind + " Index")
    result = check(callee=callee, wrapper=f"int Drive(void) {{ return Read({arguments}); }}")
    calls = result["calls"]
    if verdict is None:
        assert calls == []
    else:
        assert calls[0]["verdict"] == verdict


@pytest.mark.parametrize("expression,arguments,guard,verdict", [
    pytest.param("Value * Step", "65535, 65535, 1", "Value <= 65535 && Step <= 65535", "violation", id="promoted-multiply"),
    pytest.param("Value * Step", "2, 2, 1", "Value <= 65535 && Step <= 65535", "safe", id="safe-product"),
    pytest.param("Value * Step", "65535, 65535, 0", "Value <= 65535 && Step <= 65535", "guard-excluded", id="coupled-flag"),
    pytest.param("Value - Step", "2147483647, -1, 1", "Value >= 1", "violation", id="signed-subtraction"),
])
def test_literal_arithmetic_uses_exact_promoted_math(expression, arguments, guard, verdict):
    value_type = "unsigned short" if "*" in expression else "int"
    source = f"int Read({value_type} Value, {value_type} Step, int Flag) {{ if(Flag == 1 && {guard}) return {expression}; return 0; }}"
    result = check(callee=source, wrapper=f"int Drive(void) {{ return Read({arguments}); }}",
                   verb="check-overflow", hypothesis=f"integer overflow in `{expression}`")
    assert result["status"] == "checked", result
    assert result["calls"][0]["verdict"] == verdict
    if verdict == "violation":
        assert result["calls"][0]["mathematical_result"] > 2147483647


@pytest.mark.parametrize("lines", [[], [True], [0], list(range(1, 42)), [1]])
def test_only_bounded_exact_call_locations_can_earn_evidence(lines):
    result = check_literal_calls(ARRAY + "\nint Drive(void) { return Read(4,1); }", "Read", "check-array-bounds", HYPOTHESIS, "ilp32", lines)
    assert not result["calls"]


@pytest.mark.parametrize("changed", ["result", "range", "argument", "missing-types"])
def test_positive_overflow_call_requires_independent_exact_math(changed):
    from core.audit.literal_call import literal_call_witness_valid
    callee = "int Read(int Value, int Step) { if(Value >= 1) return Value - Step; return 0; }"
    hypothesis = "integer overflow in `Value - Step`"
    reply = check(callee=callee, wrapper="int Drive(void) { return Read(2147483647, -1); }",
                  verb="check-overflow", hypothesis=hypothesis)
    call = reply["calls"][0]
    assert literal_call_witness_valid(reply, call, "check-overflow", hypothesis, "ilp32")
    if changed == "result":
        call["mathematical_result"] = 0
    elif changed == "range":
        call["result_range"]["maximum"] = 4294967295
    elif changed == "argument":
        call["arguments"]["Step"] = 0
    else:
        del reply["parameter_types"]
    assert not literal_call_witness_valid(reply, call, "check-overflow", hypothesis, "ilp32")


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_literal_call_requires_a_visible_supported_callee(language):
    if language == "cpp":
        pytest.importorskip("tree_sitter_cpp")
    callee = "int Read(int Value, int Step) { if(Value >= 1) return Value - Step; return 0; }"
    wrapper = "int Drive(void) { return Read(2147483647, -1); }"
    hypothesis = "integer overflow in `Value - Step`"
    result = check_literal_calls(
        wrapper + "\n" + callee, "Read", "check-overflow", hypothesis, "ilp32", [1], language,
    )
    assert result["status"] == "checked"
    assert result["calls"] == []
    control = check(callee=callee, wrapper=wrapper, verb="check-overflow",
                    hypothesis=hypothesis, language=language)
    assert control["calls"][0]["verdict"] == "violation"
    assert control["calls"][0]["mathematical_result"] == 2147483648
