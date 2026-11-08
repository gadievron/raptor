"""Narrowing observations must use the declaration owning a source use."""

import pytest

from core.audit import condition_smt
from core.audit.condition_extraction import _get_parser
from core.audit.narrowing_guards import NarrowingGuardContext


@pytest.fixture(autouse=True)
def diagnostic_only(monkeypatch):
    monkeypatch.setattr(condition_smt, "_try_z3_integer_narrowing", lambda *a: None)


SCOPES = [
    "if(TYPE value=0;true){\nint small=value;\n}",
    "if(TYPE value=1){\nint small=value;\n}",
    "while(TYPE value=1){\nint small=value;\nbreak;}",
    "switch(TYPE value=0;value){case 0:\nint small=value;\n}",
    "for(TYPE value:items){\nint small=value;\n}",
    "try{}catch(TYPE value){\nint small=value;\n}",
    "auto fn=[](TYPE value){\nint small=value;\n};",
    "auto fn=[](TYPE value=0){\nint small=value;\n};",
]
IDS = ["if-init", "if-declaration", "while-declaration", "switch-init", "range-loop", "catch", "lambda", "lambda-default"]


def check(source, language="cpp"):
    parser = _get_parser(language)
    if parser is None:
        pytest.skip(f"{language} grammar required")
    assert not parser.parse(source.encode()).root_node.has_error, source
    return condition_smt.check_integer_narrowing(source, language=language)


@pytest.mark.parametrize("body", SCOPES, ids=IDS)
@pytest.mark.parametrize("outer,inner,found", [("size_t", "int", False), ("int", "size_t", True)], ids=["narrow-shadow", "wide-shadow"])
def test_control_and_callable_scopes_resolve_their_own_declared_width(body, outer, inner, found):
    source = f"void Read({outer} value){{\n" + body.replace("TYPE", inner) + "\n}"
    result = check(source)
    assert result.narrowing_found is found, result
    if found:
        assert result.source_type == "size_t"


@pytest.mark.parametrize("body", [
    "auto fn=[value=0](){\nint small=value;\n};",
    "auto fn=[&value=other](){\nint small=value;\n};",
    "auto [value,other]=items;\nint small=value;",
    "auto &[value,other]=items;\nint small=value;",
    "for(auto [value,other]:items){\nint small=value;\n}",
], ids=["init-capture", "reference-init-capture", "structured", "structured-reference", "structured-range"])
def test_unresolved_bindings_mask_outer_types(body):
    source = "void Read(size_t value){\n" + body + "\n}"
    assert not check(source).narrowing_found


@pytest.mark.parametrize("body", SCOPES, ids=IDS)
def test_outer_binding_is_restored_after_the_inner_scope(body):
    source = "void Read(size_t value){\n" + body.replace("TYPE", "int") + "\nint after=value;\n}"
    assert check(source).narrowing_found
    context = NarrowingGuardContext(source, language="cpp")
    line = next(n for n, text in enumerate(source.splitlines()) if "int after=" in text)
    column = source.splitlines()[line].index("=") + 1
    assert context.visible_types(line, column)["value"] == "size_t"


@pytest.mark.parametrize("declaration", ["long __attribute__((mode(SI))) value", "long value __attribute__((mode(SI)))"], ids=["before-name", "after-name"])
def test_unmodelled_c_attributes_do_not_supply_an_assumed_integer_width(declaration):
    source = f"int Read({declaration}){{\nint small=value;\nreturn small;\n}}"
    assert not check(source, "c").narrowing_found


def test_default_function_parameter_keeps_its_declared_type():
    assert check("void Read(size_t value=0){\nint small=value;\n}").narrowing_found


@pytest.mark.parametrize("capture", ["value", "&value", "=", "&"])
def test_ordinary_captures_keep_the_visible_width(capture):
    source = "void Read(size_t value){\nauto fn=[" + capture + "](){\nint small=value;\n};\n}"
    assert check(source).narrowing_found


@pytest.mark.parametrize("key", ["class", "struct"])
def test_scoped_enum_members_do_not_mask_an_outer_value(key):
    source = "void Read(size_t value){\nenum " + key + " E {value=0};\nint small=value;\n}"
    assert check(source).narrowing_found


@pytest.mark.parametrize("body", [
    "auto fn=[value=[&](){\nint small=value;\nreturn 0;}()](){};",
    "for(int value:[&](){\nint small=value;\nreturn items;}()){}",
], ids=["capture-initializer", "range-initializer"])
def test_initializer_uses_the_outer_scope_before_the_new_binding(body):
    assert check("void Read(size_t value){\n" + body + "\n}").narrowing_found


def test_returned_function_parameters_are_not_function_entry_inputs():
    from core.audit.arithmetic_operation import bind_arithmetic_operation

    source = "unsigned (*Read(unsigned Actual))(unsigned Value,unsigned Step){if(Value>0&&Step>0){unsigned Local=Value*Step;}return 0;}"
    result = bind_arithmetic_operation(source, ["Value", "Step"], "*", language="c", integer_abi="ilp32")
    assert result.type_status == "unavailable", result


@pytest.mark.usefixtures("overflow_disproof_unit_worker")
@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("actual,prototype,outcome", [("unsigned", "int", "refuted"), ("int", "unsigned", "confirmed")],
                         ids=["unsigned-entry", "signed-entry"])
def test_actual_function_parameters_supply_the_source_overflow_frame(language, actual, prototype, outcome):
    from core.audit import sweep

    source = (f"unsigned (*Read({actual} Value,{actual} Step))({prototype} Value,{prototype} Step)"
              + "{if(Value<10&&Step<10){" + actual + " Local=Value+Step;}return 0;}")
    result = sweep._run_smt_verb_inner(file_path="unit." + language, function_name="Read", verb="check-overflow",
                                     source=source, hypothesis="integer overflow in `Value + Step`", integer_abi="ilp32")
    assert result.outcome == outcome, result.details
    assert result.details["source_scope"]["query_contract"] == "common-width-integer-operands-v23"


def test_array_model_does_not_mistake_a_returned_function_pointer_for_an_integer():
    from core.audit.array_bounds import bind_array_access

    source = "int (*Read(int Actual))(int Index){int Data[4]={0};if(Index>=0&&Index<=4){return Data[Index];}return 0;}"
    result = bind_array_access(source, "out-of-bounds read at Data[Index]", language="c", integer_abi="ilp32")
    assert result.status == "unavailable", result


@pytest.mark.parametrize("verb,version", [("check-overflow", "common-width-integer-operands-v20"),
                                        ("check-array-bounds", "common-width-array-guards-v9")])
def test_previous_declaration_contracts_cannot_supply_worker_proof_credit(monkeypatch, verb, version):
    from dataclasses import asdict
    from core.audit import sweep
    from core.audit.probe_function_scope import source_binding, source_for_function

    source = "unsigned Read(unsigned Value,unsigned Step){if(Value<10&&Step<10){return Value+Step;}return 0;}"
    hypothesis = "integer overflow in `Value + Step`"
    if verb == "check-array-bounds":
        source = "int Read(int Index){int Data[4]={0};if(Index>=0&&Index<4){return Data[Index];}return 0;}"
        hypothesis = "out-of-bounds read at Data[Index]"
    _, selected = source_for_function(source, "unit.c", "Read")
    binding = source_binding(selected, "Read", verb=verb, integer_abi="ilp32", hypothesis=hypothesis)
    binding["query_contract"] = version
    old = sweep.SweepResult(tool="smt", file_path="unit.c", function_name="Read", rule_id="smt:" + verb,
                            outcome="refuted", details={"source_scope": binding})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **k: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path="unit.c", function_name="Read", verb=verb,
                                         source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == "inconclusive" and result.matches == []
    assert result.details["source_scope_status"] == "unbound-worker-result"


@pytest.mark.parametrize("body", [
    "if(unsigned Value=0;Step>0){return Value+Step;}",
    "auto fn=[](unsigned Value,unsigned Step){return Value+Step;};",
], ids=["local-condition-value", "nested-callable"])
def test_new_diagnostic_bindings_do_not_invent_source_entry_proofs(body):
    from core.audit.arithmetic_operation import bind_arithmetic_operation

    source = "unsigned Read(unsigned Value,unsigned Step){" + body + "return 0;}"
    result = bind_arithmetic_operation(source, ["Value", "Step"], "+", language="cpp", integer_abi="ilp32")
    assert result.type_status == "unavailable"
