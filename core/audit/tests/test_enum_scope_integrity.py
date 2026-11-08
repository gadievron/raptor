"""Enum declarations must not borrow the values or widths of outer inputs."""

import pytest

from core.audit import condition_smt
from core.audit.condition_extraction import _get_parser
from core.audit.arithmetic_operation import bind_arithmetic_operation
from core.audit.literal_call import check_literal_calls


@pytest.fixture(autouse=True)
def diagnostic_only(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


def parsed(source, language):
    parser = _get_parser(language)
    if parser is None:
        pytest.skip(f"{language} grammar required")
    assert not parser.parse(source.encode()).root_node.has_error, source
    return source


@pytest.mark.parametrize("declaration", [
    "struct S{enum{wide=0}field;};",
    "union S{enum{wide=0}field;};",
    "struct S{union U{enum{wide=0}field;}member;};",
    "typedef struct{enum{wide=0}field;}Alias;",
    "struct S{enum{wide=0}field;}object;",
    "sizeof(enum{wide=0});",
], ids=["struct", "union", "nested-record", "typedef", "object", "sizeof-type"])
def test_c_enum_constants_mask_an_outer_integer(declaration):
    source = parsed("void Read(unsigned long wide){\n{" + declaration + "\nint small=wide;\n}\n}", "c")
    assert not condition_smt.check_integer_narrowing(source, language="c").narrowing_found


@pytest.mark.parametrize("declaration", [
    "struct S{enum{wide=0}field;};",
    "union S{enum{wide=0}field;};",
    "struct S{union U{enum{wide=0}field;}member;};",
    "typedef struct{enum{wide=0}field;}Alias;",
    "struct S{enum{wide=0}field;}object;",
])
def test_cpp_record_enum_members_do_not_mask_an_outer_integer(declaration):
    source = parsed("void Read(unsigned long wide){\n{" + declaration + "\nint small=wide;\n}\n}", "cpp")
    assert condition_smt.check_integer_narrowing(source, language="cpp").narrowing_found


@pytest.mark.parametrize("declaration", [
    "{struct S{enum{wide=0}field;};}",
    "void helper(enum{wide=0}argument);",
    "int (*helper)(enum{wide=0}argument);",
    "if(sizeof(enum{wide=0})){;}",
])
def test_nested_block_and_prototype_enum_constants_do_not_escape(declaration):
    source = parsed("void Read(unsigned long wide){\n" + declaration + "\nint small=wide;\n}", "c")
    assert condition_smt.check_integer_narrowing(source, language="c").narrowing_found


@pytest.mark.parametrize("header", ["if(sizeof(enum{wide=0}))", "while(sizeof(enum{wide=0}))", "for(;sizeof(enum{wide=0});)"])
def test_c_control_header_enum_constants_are_visible_in_the_body(header):
    source = parsed("void Read(unsigned long wide){\n" + header + "{\nint small=wide;\n}\n}", "c")
    assert not condition_smt.check_integer_narrowing(source, language="c").narrowing_found


@pytest.mark.parametrize("declaration", ["struct S{enum{Wide=0}field;};", "sizeof(enum{Wide=0});"])
def test_an_enum_cannot_become_an_unconstrained_function_entry_input(declaration):
    source = parsed("unsigned Read(unsigned Wide,unsigned Step){{" + declaration
                    + "if(Wide>0&&Step>0){return Wide*Step;}}return 0;}", "c")
    result = bind_arithmetic_operation(source, ["Wide", "Step"], "*", language="c", integer_abi="ilp32")
    assert result.type_status == "unavailable", result
    source += "\nunsigned Wrap(void){return Read(2147483647,2147483647);}"
    result = check_literal_calls(source, "Read", "check-overflow", "integer overflow in `Wide * Step`", "ilp32", [2])
    assert result["status"] == "unavailable" and result["calls"] == []


@pytest.mark.usefixtures("invariant_unit_worker")
@pytest.mark.parametrize("declaration", ["enum{Limit=0};", "struct S{enum{Limit=0}field;};"])
def test_a_source_enum_guard_cannot_supply_a_free_mathematical_value(declaration):
    from core.audit.invariant_smt import check_invariant_preservation

    source = parsed(declaration + "if(Limit>0)Count++;", "c")
    result = check_invariant_preservation("Count <= Limit", source)
    assert result.outcome == "inconclusive", result.to_dict()
    assert all(site.verdict == "out_of_scope" and not site.model for site in result.sites)


def test_a_nested_enum_limit_cannot_borrow_a_standard_macro_value():
    source = parsed("void Read(unsigned wide){\nstruct S{enum{UINT8_MAX=1024}field;};\n"
                    "if(wide>UINT8_MAX)return;\nunsigned char small=wide;\n}", "c")
    assert condition_smt.check_integer_narrowing(source, language="c").narrowing_found


def test_enum_guards_cannot_be_cropped_into_free_values_by_a_protocol_snapshot():
    from core.audit.invariant_source import guard_snapshot_supported

    source = parsed("void Read(int Count){\nstruct S{enum{Limit=0}field;};\nif(Limit>0){\nCount++;\n}\n}", "c")
    assert not guard_snapshot_supported(source, "Read", 4)


def test_previous_integer_binding_contract_cannot_supply_a_worker_verdict(monkeypatch):
    from dataclasses import asdict
    from core.audit import sweep
    from core.audit.probe_function_scope import source_binding, source_for_function

    source = "unsigned Read(unsigned Wide,unsigned Step){if(Wide>0&&Step>0)return Wide*Step;return 0;}"
    _, selected = source_for_function(source, "unit.c", "Read")
    hypothesis = "integer overflow in `Wide * Step`"
    binding = source_binding(selected, "Read", verb="check-overflow", hypothesis=hypothesis, integer_abi="ilp32")
    binding["query_contract"] = "common-width-integer-operands-v21"
    old = sweep.SweepResult(tool="smt", file_path="unit.c", function_name="Read", rule_id="smt:check-overflow",
                            outcome="refuted", details={"source_scope": binding})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **k: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path="unit.c", function_name="Read", verb="check-overflow",
                                         source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == "inconclusive" and not result.matches
    assert result.details["source_scope_status"] == "unbound-worker-result"


def test_previous_literal_call_contract_cannot_promote_a_worker_counterexample(monkeypatch):
    from core.audit.literal_call_gate import evaluate_literal_caller_gate

    source = ("unsigned Read(unsigned Wide,unsigned Step){if(Wide>0&&Step>0)return Wide*Step;return 0;}"
              "\nunsigned Wrap(void){return Read(2147483647,2147483647);}")
    hypothesis = "integer overflow in `Wide * Step`"
    old = check_literal_calls(source, "Read", "check-overflow", hypothesis, "ilp32", [2])
    assert old["calls"][0]["verdict"] == "violation"
    old["binding"]["query_contract"] = "common-width-literal-frame-v7"
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *a, **k: old)
    decision = evaluate_literal_caller_gate("unit.c", "Read", "check-overflow", hypothesis,
                                          defining_source=source, source=source, integer_abi="ilp32")
    assert decision.action == "hold"


@pytest.mark.parametrize("declaration", [
    "struct wide{int wide;};",
    "struct S{int wide;};",
    "#if 0\nstruct S{enum{wide=0}field;};\n#endif",
])
def test_record_fields_tags_and_inactive_directives_do_not_hide_a_value(declaration):
    source = parsed("void Read(unsigned long wide){\n{\n" + declaration + "\nint small=wide;\n}\n}", "c")
    assert condition_smt.check_integer_narrowing(source, language="c").narrowing_found


@pytest.mark.usefixtures("invariant_unit_worker")
@pytest.mark.parametrize("declaration", ["enum{Limit=100};", "struct S{enum{Limit=100}field;};"])
def test_an_invariant_bound_cannot_range_over_arbitrary_values_of_a_source_enum(declaration):
    from core.audit.invariant_smt import check_invariant_preservation

    source = parsed(declaration + "Count=50;", "c")
    result = check_invariant_preservation("Count <= Limit", source)
    assert result.outcome == "inconclusive", result.to_dict()
    assert all(site.verdict == "out_of_scope" and not site.model for site in result.sites)
