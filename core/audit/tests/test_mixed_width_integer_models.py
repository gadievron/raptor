"""C result types come from operands, while every input keeps its storage range."""

import pytest

from core.audit import sweep
from core.audit.arithmetic_operation import bind_arithmetic_operation
from core.audit.array_bounds import check_array_bounds
from core.audit.literal_call import check_literal_calls

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.fixture(autouse=True)
def c_grammar():
    pytest.importorskip("tree_sitter_c")


def query(source, expression="Alpha * Zulu", abi="lp64", language="c"):
    return sweep._run_smt_verb_inner(file_path="unit." + language, function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=f"integer overflow in `{expression}`", integer_abi=abi)


@pytest.mark.parametrize("abi,profile,verdict", [("lp64", "int64", "refuted"), ("llp64", "int32", "confirmed"),
                                              ("ilp32", "int32", "confirmed"), ("i16", "int32", "refuted")])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_same_source_uses_the_target_common_operand_type(abi, profile, verdict, language):
    pytest.importorskip("tree_sitter_" + language)
    pytest.importorskip("z3")
    limit = 32767 if abi == "i16" else 65535
    source = f"long Read(int Alpha,long Zulu){{ if(Alpha>=0 && Alpha<={limit} && Zulu>=0 && Zulu<={limit}) return Alpha * Zulu; return 0; }}"
    result = query(source, abi=abi, language=language)
    assert result.outcome == verdict, result.details
    assert result.details["source_operation"]["profile"] == profile


@pytest.mark.parametrize("operator", ["+", "-", "*"])
def test_real_mixed_width_overflow_has_an_independently_checked_witness(operator):
    pytest.importorskip("z3")
    guard = "Alpha == 2 && Zulu > 0" if operator != "-" else "Alpha == 2 && Zulu < 0"
    source = f"long Read(int Alpha,long Zulu){{ if({guard}) return Alpha {operator} Zulu; return 0; }}"
    result = query(source, f"Alpha {operator} Zulu")
    assert result.outcome == "confirmed", result.details
    model = result.details["model"]
    assert -2147483648 <= model["Alpha"] <= 2147483647
    assert result.details["witness_validated"] is True
    assert not -(1 << 63) <= result.details["mathematical_result"] <= (1 << 63) - 1


def test_narrow_operand_domain_prevents_a_spurious_wide_overflow():
    pytest.importorskip("z3")
    source = "long Read(int Alpha,long Zulu){ if(Zulu==1) return Alpha + Zulu; return 0; }"
    result = query(source, "Alpha + Zulu")
    assert result.outcome == "refuted", result.details
    assert result.details["source_operation"]["domains"] == ["Alpha >= (0 - 2147483648)", "Alpha <= 2147483647"]


@pytest.mark.parametrize("abi,profile", [("lp64", "uint64"), ("llp64", "uint32")])
def test_unsigned_width_conversion_retains_the_narrow_unsigned_domain(abi, profile):
    pytest.importorskip("z3")
    source = "unsigned long Read(unsigned Alpha,unsigned long Zulu){ if(Zulu==0) return Alpha + Zulu; return 0; }"
    result = query(source, "Alpha + Zulu", abi=abi)
    assert result.outcome == "refuted", result.details
    assert result.details["source_operation"]["profile"] == profile
    if abi == "lp64":
        assert result.details["source_operation"]["domains"] == ["Alpha >= 0", "Alpha <= 4294967295"]


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_wide_array_index_with_narrow_guard_parameter(language):
    pytest.importorskip("tree_sitter_" + language)
    pytest.importorskip("z3")
    source = "int Read(long Index,int Flag){ int Data[4]={0}; if(Flag==1 && Index>=0 && Index<=4) return Data[Index]; return 0; }"
    result = check_array_bounds(source, "Data[Index] out-of-bounds read", language=language, integer_abi="lp64")
    assert result["violation"] is True, result
    assert result["source_access"]["profile"] == "int64"
    assert result["source_access"]["width"] == 64
    assert result["model"]["Flag"] == 1 and result["witness_index"] == 4


def test_guard_width_cannot_widen_the_operation_result_type():
    source = "int Read(int Alpha,int Zulu,long WideFlag){ if(WideFlag==1 && Alpha>0 && Zulu>0) return Alpha * Zulu; return 0; }"
    operation = bind_arithmetic_operation(source, ["Alpha", "Zulu"], "*", language="c", integer_abi="lp64")
    assert operation.type_status == "unavailable"  # wider guards need a separate comparison encoding


def test_safe_mixed_literal_tuple_is_not_checked_at_the_first_parameter_width():
    source = "long Read(int Alpha,long Zulu){ return Alpha + Zulu; }\nint Drive(void){return Read(2147483647,1);}"
    result = check_literal_calls(source, "Read", "check-overflow", "integer overflow in `Alpha + Zulu`", "lp64", [2])
    assert result["status"] == "checked", result
    assert result["calls"][0]["verdict"] == "safe"
    assert result["calls"][0]["mathematical_result"] == 2147483648
    assert result["calls"][0]["result_range"] == {"minimum": -(1 << 63), "maximum": (1 << 63) - 1}


@pytest.mark.parametrize("left,right,abi,profile", [
    ("int", "long", "lp64", "int64"), ("long", "int", "lp64", "int64"),
    ("int", "long long", "llp64", "int64"), ("signed char", "long", "lp64", "int64"),
    ("unsigned short", "long", "lp64", "int64"), ("unsigned short", "long", "i16", None),
    ("unsigned", "unsigned long", "lp64", "uint64"),
    ("unsigned long", "unsigned", "lp64", "uint64"),
    ("unsigned", "unsigned long long", "llp64", "uint64"),
    ("int", "unsigned long", "lp64", None), ("long", "unsigned", "lp64", None),
    ("int", "long", "ilp64", "int64"), ("int", "long", "i16", "int32"),
])
def test_operand_conversion_profiles_preserve_promotions_and_decline_mixed_signs(left, right, abi, profile):
    source = f"long long Read({left} Alpha,{right} Zulu){{ if(Alpha>0 && Zulu>0) return Alpha + Zulu; return 0; }}"
    operation = bind_arithmetic_operation(source, ["Alpha", "Zulu"], "+", language="c", integer_abi=abi)
    assert operation.type_status == ("bound" if profile else "unavailable")
    if profile:
        assert operation.profile == profile


@pytest.mark.parametrize("expression", ["Alpha + 1", "1 + Alpha", "Alpha - 1", "1 - Alpha"])
def test_small_int_literal_preserves_the_wider_operand_type(expression):
    pytest.importorskip("z3")
    source = f"long Read(long Alpha){{ if(Alpha>=0 && Alpha<=65535) return {expression}; return 0; }}"
    result = query(source, expression)
    assert result.outcome == "refuted", result.details
    assert result.details["source_operation"]["profile"] == "int64"


@pytest.mark.parametrize("operator,guard", [("+", "Alpha == 2 && Zulu > 0"),
                                           ("-", "Alpha == 2 && Zulu < 0"),
                                           ("-", "Alpha == -2 && Zulu > 0")])
def test_mixed_addition_and_subtraction_keep_checked_counterexamples(operator, guard):
    pytest.importorskip("z3")
    from core.audit.condition_smt import disprove_integer_overflow
    source = f"long Read(int Alpha,long Zulu){{ if({guard}) return Zulu {operator} Alpha; return 0; }}"
    expression = f"Zulu {operator} Alpha"
    result = query(source, expression)
    assert result.outcome == "confirmed", result.details
    auxiliary = disprove_integer_overflow(f"integer overflow in `{expression}`", source,
                                          file_path="unit.c", function_name="Read", integer_abi="lp64")
    assert auxiliary.disproved is False


@pytest.mark.parametrize("operator", ["+", "*"])
def test_mixed_unsigned_counterexample_keeps_the_complete_unsigned_range(operator):
    pytest.importorskip("z3")
    source = f"unsigned long Read(unsigned Alpha,unsigned long Zulu){{ if(Alpha==2 && Zulu>0) return Alpha {operator} Zulu; return 0; }}"
    result = query(source, f"Alpha {operator} Zulu")
    assert result.outcome == "confirmed", result.details
    assert 0 <= result.details["model"]["Alpha"] <= 4294967295
    assert result.details["mathematical_result"] > (1 << 64) - 1


@pytest.mark.parametrize("damage", ["profile", "kind", "in-range", "narrow-domain"])
def test_independent_evaluator_rejects_the_wrong_range_or_assignment(damage):
    from dataclasses import replace
    from core.audit.integer_witness import validate_overflow_result
    source = "long Read(int Alpha,long Zulu){ if(Alpha>0 && Zulu>0) return Alpha + Zulu; return 0; }"
    operation = bind_arithmetic_operation(source, ["Alpha", "Zulu"], "+", language="c", integer_abi="lp64")
    model = {"Alpha": 1, "Zulu": (1 << 63) - 1}
    if damage == "profile":
        operation = replace(operation, profile="int32")
    elif damage == "kind":
        operation = replace(operation, kind="unsigned_wrap")
    elif damage == "in-range":
        model = {"Alpha": 2147483647, "Zulu": 1}
    else:
        model["Alpha"] = 1 << 40
    result = validate_overflow_result({"feasible": True, "model": model}, operation, ["Alpha", "Zulu"], "+", "lp64")
    assert result["feasible"] is None and result["witness_validated"] is False


@pytest.mark.parametrize("guard", ["Index>=0 && Index<4", "Flag>127 && Index>=0 && Index<=4"])
def test_wide_array_access_keeps_safe_and_unreachable_obligations_distinct(guard):
    pytest.importorskip("z3")
    source = f"int Read(long Index,signed char Flag){{ int Data[4]={{0}}; if({guard}) return Data[Index]; return 0; }}"
    result = check_array_bounds(source, "Data[Index] out-of-bounds read", language="c", integer_abi="lp64")
    assert result["violation"] is (None if "Flag>127" in guard else False), result
    assert "model" not in result


def test_auxiliary_wider_array_guard_does_not_change_the_index_solver_width():
    source = "int Read(int Index,long Flag){ int Data[4]={0}; if(Flag==1 && Index>=0 && Index<=4) return Data[Index]; return 0; }"
    result = check_array_bounds(source, "Data[Index] out-of-bounds read", language="c", integer_abi="lp64")
    assert result["array_bounds_status"] == "unavailable"


@pytest.mark.slow
@pytest.mark.parametrize("guard,outcome", [("Alpha==2 && Zulu>0", "confirmed"), ("Zulu==1", "refuted")])
def test_confined_overflow_worker_uses_the_common_operand_width(guard, outcome):
    pytest.importorskip("z3")
    source = f"long Read(int Alpha,long Zulu){{ if({guard}) return Alpha + Zulu; return 0; }}"
    result = sweep.run_smt_verb_direct(file_path="unit.c", function_name="Read", verb="check-overflow",
                                      source=source, hypothesis="integer overflow in `Alpha + Zulu`", integer_abi="lp64")
    assert result.outcome == outcome, result.details
    assert result.details["source_operation"]["profile"] == "int64"
    assert result.details["source_scope"]["query_contract"] == "common-width-integer-operands-v25"


@pytest.mark.slow
@pytest.mark.parametrize("upper,outcome", [("<=", "confirmed"), ("<", "inconclusive")])
def test_confined_array_worker_keeps_narrow_guards_in_the_wide_index_frame(upper, outcome):
    pytest.importorskip("z3")
    source = f"int Read(long Index,int Flag){{ int Data[4]={{0}}; if(Flag==1 && Index>=0 && Index{upper}4) return Data[Index]; return 0; }}"
    result = sweep.run_smt_verb_direct(file_path="unit.c", function_name="Read", verb="check-array-bounds",
                                      source=source, hypothesis="Data[Index] out-of-bounds read", integer_abi="lp64")
    assert result.outcome == outcome, result.details
    assert result.details["source_access"]["profile"] == "int64"
    assert result.details["source_scope"]["query_contract"] == "common-width-array-guards-v17"
    assert result.details["violation"] is (outcome == "confirmed")
    if outcome == "confirmed":
        assert result.details["witness_index"] == 4


@pytest.mark.slow
@pytest.mark.parametrize("index,action", [(4, "promote"), (3, "hold")])
def test_confined_literal_call_frame_keeps_mixed_width_parameter_guards(tmp_path, index, action):
    from core.audit.smt_promotion_gate import evaluate_caller_gate
    source = ("int Read(long Index,int Flag){ int Data[4]={0}; if(Flag==1 && Index>=0 && Index<=4) return Data[Index]; return 0; }\n"
              f"int Drive(void){{ return Read({index},1); }}\n")
    (tmp_path / "unit.c").write_text(source)
    decision = evaluate_caller_gate(tmp_path, "unit.c", "Read", "check-array-bounds", "Data[Index] out-of-bounds read",
                                    source=source, integer_abi="lp64")
    assert decision.action == action, decision.reason
    assert decision.details["binding"]["query_contract"] == "common-width-literal-frame-v17"
    assert decision.details["callee_obligation"]["profile"] == "int64"
    assert decision.details["status"] == "checked"
    assert decision.details["proof_scope"] == "caller-entry-source-model"
    assert dict(decision.details["parameter_types"]) == {"Index": "long", "Flag": "int"}
    assert len(decision.details["calls"]) == 1
    call = decision.details["calls"][0]
    assert call["arguments"] == {"Index": index, "Flag": 1}
    assert call["verdict"] == ("violation" if action == "promote" else "safe")


def test_guard_only_first_declaration_cannot_choose_the_literal_arithmetic_range():
    source = ("long Read(int Alpha,long Yankee,long Zulu){ if(Alpha==1) return Yankee + Zulu; return 0; }\n"
              "int Drive(void){return Read(1,2147483647,1);}")
    result = check_literal_calls(source, "Read", "check-overflow", "integer overflow in `Yankee + Zulu`", "lp64", [2])
    assert result["calls"][0]["verdict"] == "safe", result
    assert result["calls"][0]["result_range"]["maximum"] == (1 << 63) - 1
