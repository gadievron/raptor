"""Real source access obligations, with type, guard and object provenance."""

import pytest

from core.audit import array_bounds as bounds
from core.audit import sweep


@pytest.fixture(autouse=True)
def parsers():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


def source(body="return Data[Index];", index_type="int", extent="4"):
    return f"int Read({index_type} Index, int Flag) {{ int Data[{extent}] = {{0}}; {body} }}"


@pytest.mark.parametrize("body,feasible,direction", [
    pytest.param("return Data[Index];", True, "either", id="unguarded"),
    pytest.param("if(Index >= 0 && Index <= 4) return Data[Index]; return 0;", True, "upper", id="off-by-one"),
    pytest.param("if(Index < 4) return Data[Index]; return 0;", True, "negative", id="missing-lower-bound"),
    pytest.param("if(Index >= 0) return Data[Index]; return 0;", True, "upper", id="missing-upper-bound"),
    pytest.param("if(Index >= 0 && Index < 4) return Data[Index]; return 0;", False, "none", id="both-bounds"),
    pytest.param("if(Index < 0 || Index >= 4) return 0; return Data[Index];", False, "none", id="early-return"),
    pytest.param("if(Flag == 1) return Data[Index]; return 0;", True, "either", id="unrelated-reaching-guard"),
])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_actual_access_has_a_source_linked_counterexample_or_safe_obligation(body, feasible, direction, language):
    if language == "cpp":
        pytest.importorskip("tree_sitter_cpp")
    pytest.importorskip("z3")
    text = source(body)
    result = bounds.check_array_bounds(text, "out-of-bounds read at `Data[Index]`", language=language, integer_abi="ilp32")
    assert result["array_bounds_status"] == "checked", result
    assert result["violation"] is feasible
    access = result["source_access"]
    assert access["extent"] == 4 and access["index"] == "Index" and access["object_name"] == "Data"
    assert result["proof_scope"] == "function-entry-source-model"
    if feasible:
        value = result["witness_index"]
        assert value < 0 or value >= 4
        if direction == "negative":
            assert value < 0
        if direction == "upper":
            assert value >= 4
        if "Flag == 1" in body:
            assert result["model"]["Flag"] == 1
        assert set(result["model"]) >= {"Index", "Flag"}
    else:
        assert "model" not in result


@pytest.mark.parametrize("index_type,extent,profile,feasible", [
    ("unsigned char", "4", "int32", True), ("unsigned char", "300", "int32", False),
    ("signed char", "4", "int32", True), ("_Bool", "4", "int32", False),
])
def test_promoted_types_keep_their_source_value_domains(index_type, extent, profile, feasible):
    pytest.importorskip("z3")
    result = bounds.check_array_bounds(source(index_type=index_type, extent=extent), "Data[Index] out of bounds",
                                       language="c", integer_abi="ilp32")
    assert result["violation"] is feasible, result
    assert result["source_access"]["profile"] == profile
    if feasible:
        value = result["witness_index"]
        assert (-128 <= value <= 127) if index_type == "signed char" else (0 <= value <= 255)


def test_unreachable_access_keeps_all_path_constraints():
    pytest.importorskip("z3")
    result = bounds.check_array_bounds(source("if(Flag > 10 && Flag < 5) return Data[Index]; return 0;"),
                                       "Data[Index] out of bounds", language="c", integer_abi="ilp32")
    assert result["array_bounds_status"] == "checked"
    assert result["entry_feasible"] is False
    assert result["violation"] is None
    assert "model" not in result


@pytest.mark.parametrize("text,hypothesis", [
    pytest.param("int Read(int Index, int *Data) { return Data[Index]; }", "Data[Index]", id="pointer"),
    pytest.param("int Read(int Index, int Data[4]) { return Data[Index]; }", "Data[Index]", id="array-parameter-is-pointer"),
    pytest.param(source("Index = 0; return Data[Index];"), "Data[Index]", id="assigned-index"),
    pytest.param(source("if(Flag != 2147483647) return 0; if(Flag + 1 > 0) {} return Data[Index];"), "Data[Index]", id="prior-undefined-arithmetic"),
    pytest.param(source("refresh(); return Data[Index];"), "Data[Index]", id="unknown-call"),
    pytest.param(source("for(; Index < 4; ++Index) {} return Data[Index];"), "Data[Index]", id="loop"),
    pytest.param(source("return Data[Index + 1];"), "Data[Index]", id="compound-index"),
    pytest.param(source("return sizeof(Data[Index]);"), "Data[Index]", id="unevaluated"),
    pytest.param(source("return &Data[Index];"), "Data[Index]", id="address-is-not-read"),
    pytest.param(source("if(Flag) return Data[Index]; return Data[Index];"), "Data[Index]", id="multiple-accesses"),
    pytest.param(source(), "Other[Index]", id="wrong-object"),
    pytest.param(source(), "Data[index]", id="wrong-index-case"),
    pytest.param(source(), "Data[Index] and Other[Index]", id="ambiguous-claim"),
    pytest.param(source(extent="Flag"), "Data[Index]", id="variable-extent"),
    pytest.param(source(extent="0"), "Data[Index]", id="zero-extent"),
    pytest.param(source(extent="04"), "Data[Index]", id="ambiguous-octal"),
    pytest.param(source(extent="4U"), "Data[Index]", id="literal-suffix"),
    pytest.param(source(index_type="size_t"), "Data[Index]", id="unresolved-type-alias"),
    pytest.param(source().replace("Index", "Null"), "Data[Null]", id="reserved-parser-identifier"),
    pytest.param(source("if(Index >= 0 || Flag > 0) return Data[Index]; return 0;"), "Data[Index]", id="disjunctive-path"),
])
def test_unsupported_frames_never_grant_proof(text, hypothesis):
    result = bounds.check_array_bounds(text, hypothesis, language="c", integer_abi="ilp32")
    assert result["array_bounds_status"] == "unavailable", result
    assert result["violation"] is None


@pytest.mark.parametrize("abi", ["ilp32", "i16"])
def test_target_promotions_are_bound_to_the_selected_abi(abi):
    pytest.importorskip("z3")
    text = "int Read(unsigned short Index) { int Data[4]={0}; if(Index <= 4) return Data[Index]; return 0; }"
    result = bounds.check_array_bounds(text, "Data[Index]", language="c", integer_abi=abi)
    assert result["violation"] is True
    assert result["witness_index"] == 4
    assert result["source_access"]["profile"] == ("uint16" if abi == "i16" else "int32")


@pytest.mark.parametrize("model,unknown", [
    ({"Index": 0, "Flag": 0}, []), ({"Index": 5, "Flag": 0}, []),
    ({"Index": 4, "Flag": 0}, ["unencoded"]), ({"Index": "4", "Flag": 0}, []),
])
def test_solver_output_must_independently_satisfy_the_source_obligation(monkeypatch, model, unknown):
    pytest.importorskip("z3")
    from core.smt_solver.path_feasibility import PathSMTResult

    result = PathSMTResult(feasible=True, model=model, unknown=unknown, satisfied=[], unsatisfied=[], smt_available=True, reasoning="test result")
    monkeypatch.setattr(bounds, "_solve_access", lambda access: (None, result))
    checked = bounds.check_array_bounds(source("if(Index >= 0 && Index <= 4) return Data[Index]; return 0;"),
                                        "Data[Index]", language="c", integer_abi="ilp32")
    assert checked["violation"] is None
    assert "model" not in checked


def test_missing_abi_or_parser_never_runs_a_solver(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unknown source context must not solve")
    monkeypatch.setattr(bounds, "_solve_access", forbidden)
    assert bounds.check_array_bounds(source(), "Data[Index]", language="c")["violation"] is None
    monkeypatch.setattr(bounds, "_get_parser", lambda language: None)
    assert bounds.check_array_bounds(source(), "Data[Index]", language="c", integer_abi="ilp32")["violation"] is None


def test_narrow_overflow_cannot_borrow_an_unreachable_unrelated_branch():
    pytest.importorskip("z3")
    from core.audit.condition_smt import disprove_integer_overflow

    text = "int Read(unsigned short Value, int Flag) { if(Flag > 10 && Flag < 5) return Value * Value; return 0; }"
    hypothesis = "integer overflow in `Value * Value`"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=text, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == "inconclusive"
    assert disprove_integer_overflow(hypothesis, text, file_path="record.c", function_name="Read", integer_abi="ilp32").disproved is None


def test_pre_guard_mutation_requires_a_value_flow_model():
    pytest.importorskip("z3")
    text = "int Read(unsigned short Value) { Value = 0; if(Value <= 65535) return Value * Value; return 0; }"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=text, hypothesis="integer overflow in `Value * Value`", integer_abi="ilp32")
    assert result.outcome == "inconclusive"


def test_read_obligation_does_not_verify_a_write_claim():
    result = bounds.check_array_bounds(source(), "out-of-bounds write at Data[Index]", language="c", integer_abi="ilp32")
    assert result["violation"] is None
    assert result["array_bounds_status"] == "unavailable"


@pytest.mark.parametrize("claim", ["$Data[Index]", "Ns::Data[Index]", "Ns :: Data[Index]", "obj . Data[Index]"])
def test_access_claim_never_borrows_a_name_from_a_qualified_object(claim):
    assert bounds.parse_array_access_claim(claim) is None


@pytest.mark.parametrize("name", ["NULL", "Null", "null"])
def test_source_integer_terms_cannot_collide_with_solver_literal_aliases(name):
    pytest.importorskip("z3")
    text = f"int Read(int {name}, int Step) {{ if({name} >= 0 && {name} < 4 && Step <= 1) return {name} + Step; return 0; }}"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=text, hypothesis=f"integer overflow in `{name} + Step`", integer_abi="ilp32")
    assert result.outcome == "inconclusive"


def test_preceding_undefined_arithmetic_is_not_hidden_by_a_nonreaching_guard():
    text = source("if(Flag != 2147483647) return 0; if(Flag + 1 > 0) {} return Data[Index];")
    assert bounds.check_array_bounds(text, "Data[Index]", language="c", integer_abi="ilp32")["violation"] is None
