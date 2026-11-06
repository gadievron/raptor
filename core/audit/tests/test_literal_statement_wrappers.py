"""Unconditional void wrappers preserve the complete literal call obligation."""

import pytest

from core.audit.literal_call import check_literal_calls, literal_call_witness_valid
from core.audit.tests.test_literal_call import ARRAY, HYPOTHESIS


@pytest.mark.parametrize("wrapper", ["void Drive(void){ Read(4,1); }", "void Drive(void){ (Read(4,1)); return; }"])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_void_wrapper_can_discard_a_callee_result(wrapper, language):
    pytest.importorskip("tree_sitter_" + language)
    result = check_literal_calls(ARRAY + "\n" + wrapper, "Read", "check-array-bounds", HYPOTHESIS, "ilp32", [2], language)
    assert result["status"] == "checked"
    assert result["calls"][0]["verdict"] == "violation"
    assert literal_call_witness_valid(result, result["calls"][0], "check-array-bounds", HYPOTHESIS, "ilp32")


@pytest.mark.parametrize("wrapper", ["void Drive(void){ Multiply(65535,65535); }",
                                    "void Drive(void){ return Multiply(65535,65535); }"])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_void_callee_still_has_an_arithmetic_obligation(wrapper, language):
    pytest.importorskip("tree_sitter_" + language)
    source = "void Multiply(unsigned short Value,unsigned short Step){ int Product=Value * Step; }\n" + wrapper
    result = check_literal_calls(source, "Multiply", "check-overflow", "integer overflow in `Value * Step`", "ilp32", [2], language)
    if language == "c" and "return Multiply" in wrapper:
        assert result["calls"] == []  # ISO C forbids void-valued returns
    else:
        assert result["calls"][0]["verdict"] == "violation"
        assert result["calls"][0]["mathematical_result"] == 65535 ** 2


@pytest.mark.parametrize("wrapper", [
    "int Drive(void){ Read(4,1); }", "void Drive(void){ return Read(4,1); }",
    "void Drive(void){ if(0) Read(4,1); }", "void Drive(void){ Before(); Read(4,1); }",
    "void Drive(void){ Read(4,1); After(); }", "void Drive(void){ Read(4,1); return 1; }",
    "void Drive(void){ return; Read(4,1); }", "void Drive(void){ int X=0; Read(4,1); }",
    "int Drive(int Read){ return Read(4,1); }",
])
def test_extra_execution_or_invalid_return_frame_is_not_admitted(wrapper):
    pytest.importorskip("tree_sitter_c")
    result = check_literal_calls(ARRAY + "\n" + wrapper, "Read", "check-array-bounds", HYPOTHESIS, "ilp32", [2])
    assert not result["calls"]


@pytest.mark.parametrize("wrapper", ["int Drive(int Unused){ return Read(4,1); }",
                                    "void Drive(unsigned short Unused){ Read(4,1); return; }",
                                    "int Drive(int Index,int Flag){ return Read(4,1); }"])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_unused_scalar_parameters_do_not_restrict_a_literal_call(wrapper, language):
    pytest.importorskip("tree_sitter_" + language)
    result = check_literal_calls(ARRAY + "\n" + wrapper, "Read", "check-array-bounds", HYPOTHESIS, "ilp32", [2], language)
    assert result["calls"][0]["verdict"] == "violation"
    assert result["calls"][0]["arguments"] == {"Index": 4, "Flag": 1}


def test_void_callee_returning_an_arithmetic_value_is_not_a_supported_frame():
    pytest.importorskip("tree_sitter_cpp")
    source = "void Multiply(int Value,int Step){ return Value * Step; }\nvoid Drive(void){Multiply(65535,65535);}"
    result = check_literal_calls(source, "Multiply", "check-overflow", "Value * Step", "ilp32", [2], "cpp")
    assert result["status"] == "unavailable"


@pytest.mark.slow
@pytest.mark.parametrize("step,action", [(65535, "promote"), (1, "hold")])
def test_native_void_callee_and_unused_wrapper_parameter(tmp_path, step, action):
    pytest.importorskip("tree_sitter_c")
    from core.audit.smt_promotion_gate import evaluate_caller_gate
    source = ("void Multiply(unsigned short Value,unsigned short Step){ int Product=Value * Step; }\n"
              f"void Drive(int Unused){{ Multiply(65535,{step}); return; }}\n")
    (tmp_path / "unit.c").write_text(source)
    result = evaluate_caller_gate(tmp_path, "unit.c", "Multiply", "check-overflow", "integer overflow in `Value * Step`",
                                  source=source, integer_abi="ilp32")
    assert result.action == action, result.reason
    assert result.details["proof_scope"] == "caller-entry-source-model"
