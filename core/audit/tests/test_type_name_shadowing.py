"""Type declarations and imports cannot borrow an outer value's layout."""

import pytest

from core.audit.condition_extraction import _get_parser
from core.audit.arithmetic_operation import bind_arithmetic_operation
from core.audit.arithmetic_prefix import PrefixIntegerModel
from core.audit.integer_abi import resolve_integer_abi
from core.audit.literal_call import check_literal_calls


TYPE_DECLARATIONS = [
    pytest.param("c", "typedef char Name[1024];", id="c-array-typedef"),
    pytest.param("c", "typedef char *Name;", id="c-pointer-typedef"),
    pytest.param("c", "typedef char (*Name)(int);", id="c-function-pointer-typedef"),
    pytest.param("cpp", "typedef char Name[1024];", id="cpp-array-typedef"),
    pytest.param("cpp", "using Name=char[1024];", id="cpp-array-alias"),
    pytest.param("cpp", "using Alias=struct Name{char Data[1024];};", id="cpp-alias-record-definition"),
    pytest.param("cpp", "typedef struct Name{char Data[1024];}Alias;", id="cpp-typedef-record-definition"),
    pytest.param("cpp", "struct Name{char Data[1024];};", id="cpp-struct"),
    pytest.param("cpp", "union Name{char Data[1024];};", id="cpp-union"),
    pytest.param("cpp", "class Name{char Data[1024];};", id="cpp-class"),
    pytest.param("cpp", "enum Name{Tag=0};", id="cpp-enum-type"),
    pytest.param("cpp", "enum class Name{Tag=0};", id="cpp-scoped-enum-type"),
    pytest.param("cpp", "using Scope::Name;", id="cpp-qualified-import"),
]


def parse(source, language):
    parser = _get_parser(language)
    if parser is None:
        pytest.skip(f"{language} grammar required")
    data = source.encode()
    tree = parser.parse(data).root_node
    assert not tree.has_error, source
    return data, tree


def sizes(source, language):
    data, tree = parse(source, language)
    model = PrefixIntegerModel(data, language, resolve_integer_abi("ilp32"))
    nodes, pending = [], [tree]
    while pending:
        node = pending.pop()
        if node.type == "sizeof_expression":
            nodes.append(node)
        pending.extend(reversed(node.named_children))
    return [model.value_domain(node) for node in nodes]


def function(declaration, initialiser="signed char Local=sizeof(Name);"):
    return ("unsigned Read(unsigned char Name,unsigned A,unsigned B){{" + declaration + initialiser
            + "if(A>0&&B>0)return A*B;}return 0;}")


@pytest.mark.parametrize("language,declaration", TYPE_DECLARATIONS)
def test_type_names_and_imports_do_not_inherit_the_parameter_storage_size(language, declaration):
    source = function(declaration)
    assert sizes(source, language) == [(0, None)]
    result = bind_arithmetic_operation(source, ["A", "B"], "*", language=language, integer_abi="ilp32")
    assert result.type_status == "unavailable", result
    if language == "c":
        source += "\nunsigned Wrap(void){return Read(0,2147483647,2147483647);}"
        reply = check_literal_calls(source, "Read", "check-overflow", "integer overflow in `A * B`", "ilp32", [2])
        assert reply["status"] == "unavailable" and reply["calls"] == []


@pytest.mark.parametrize("language,declaration", TYPE_DECLARATIONS)
def test_an_inner_type_name_stops_hiding_a_parameter_after_its_scope(language, declaration):
    source = "unsigned Read(unsigned char Name){ {" + declaration + "}return sizeof(Name);}"
    assert sizes(source, language) == [(1, 1)]


@pytest.mark.parametrize("language,declaration", TYPE_DECLARATIONS)
def test_unused_type_declarations_do_not_invalidate_unrelated_entry_inputs(language, declaration):
    source = function(declaration, initialiser="")
    parse(source, language)
    result = bind_arithmetic_operation(source, ["A", "B"], "*", language=language, integer_abi="ilp32")
    assert result.type_status == "bound", result


@pytest.mark.parametrize("declaration", ["struct Name{char Data[1024];};", "union Name{char Data[1024];};", "enum Name{Tag=0};",
                                          "typedef struct Name{char Data[1024];}Alias;"])
def test_c_tags_keep_their_separate_namespace(declaration):
    source = function(declaration)
    assert sizes(source, "c") == [(1, 1)]
    assert bind_arithmetic_operation(source, ["A", "B"], "*", language="c", integer_abi="ilp32").type_status == "bound"


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_a_typedef_name_begins_after_its_array_declarator(language):
    source = "unsigned Read(unsigned char Name){{typedef char Name[sizeof(Name)];return sizeof(Name);}return 0;}"
    assert sizes(source, language) == [(1, 1), (0, None)]


@pytest.mark.parametrize("declaration", ["using Scope::A;", "using enum Scope::E;"])
def test_imported_values_cannot_become_function_entry_parameters(declaration):
    source = "unsigned Read(unsigned E,unsigned A,unsigned B){{" + declaration + "if(A>0&&B>0)return A*B;}return 0;}"
    parse(source, "cpp")
    result = bind_arithmetic_operation(source, ["A", "B"], "*", language="cpp", integer_abi="ilp32")
    assert result.type_status == "unavailable", result


def test_a_namespace_directive_does_not_bind_a_new_local_scalar_name():
    source = "unsigned Read(unsigned char Scope){using namespace Scope;return sizeof(Scope);}"
    assert sizes(source, "cpp") == [(1, 1)]


def test_a_defined_unsigned_conversion_does_not_need_an_unknown_size_to_fit():
    source = function("typedef char Name[1024];", "unsigned char Local=sizeof(Name);")
    result = bind_arithmetic_operation(source, ["A", "B"], "*", language="c", integer_abi="ilp32")
    assert result.type_status == "bound", result


def test_previous_integer_contract_cannot_supply_a_worker_verdict(monkeypatch):
    from dataclasses import asdict
    from core.audit import sweep
    from core.audit.probe_function_scope import source_binding, source_for_function

    source = function("", initialiser="")
    parse(source, "c")
    _, selected = source_for_function(source, "unit.c", "Read")
    hypothesis = "integer overflow in `A * B`"
    binding = source_binding(selected, "Read", verb="check-overflow", hypothesis=hypothesis, integer_abi="ilp32")
    binding["query_contract"] = "common-width-integer-operands-v22"
    old = sweep.SweepResult(tool="smt", file_path="unit.c", function_name="Read", rule_id="smt:check-overflow",
                            outcome="refuted", details={"source_scope": binding})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **k: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path="unit.c", function_name="Read", verb="check-overflow",
                                         source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == "inconclusive" and not result.matches
    assert result.details["source_scope_status"] == "unbound-worker-result"


def test_previous_literal_contract_cannot_promote_a_worker_counterexample(monkeypatch):
    from core.audit import condition_smt
    from core.audit.literal_call_gate import evaluate_literal_caller_gate

    source = function("", initialiser="") + "\nunsigned Wrap(void){return Read(0,2147483647,2147483647);}"
    parse(source, "c")
    hypothesis = "integer overflow in `A * B`"
    old = check_literal_calls(source, "Read", "check-overflow", hypothesis, "ilp32", [2])
    assert old["calls"][0]["verdict"] == "violation"
    old["binding"]["query_contract"] = "common-width-literal-frame-v8"
    monkeypatch.setattr(condition_smt, "_run_z3_child", lambda *a, **k: old)
    decision = evaluate_literal_caller_gate("unit.c", "Read", "check-overflow", hypothesis,
                                          defining_source=source, source=source, integer_abi="ilp32")
    assert decision.action == "hold"


@pytest.mark.usefixtures("overflow_disproof_unit_worker")
@pytest.mark.parametrize("language,source", [
    ("c", function("typedef char Name[1024];")),
    ("cpp", "unsigned Read(unsigned E,unsigned A,unsigned B){{using Scope::A;if(A>0&&B>0)return A*B;}return 0;}"),
    ("cpp", "unsigned Read(unsigned E,unsigned A,unsigned B){{using enum Scope::E;if(A>0&&B>0)return A*B;}return 0;}"),
], ids=["typedef-layout", "imported-value", "enum-import"])
def test_real_overflow_producer_refuses_unresolved_lookup_or_layout(language, source):
    from core.audit import sweep

    parse(source, language)
    result = sweep._run_smt_verb_inner(file_path="unit." + language, function_name="Read", verb="check-overflow",
                                     source=source, hypothesis="integer overflow in `A * B`", integer_abi="ilp32")
    assert result.outcome == "inconclusive" and not result.matches, result.details


@pytest.mark.parametrize("declaration,admitted", [
    ("using Alias=enum Type{A=0};", False),
    ("using Alias=enum class Type{A=0};", True),
    ("using Alias=struct Type{enum{A=0}field;};", True),
], ids=["unscoped-enum", "scoped-enum", "record-member"])
def test_types_defined_by_an_alias_respect_enumerator_scope(declaration, admitted):
    source = "unsigned Read(unsigned A,unsigned B){{" + declaration + "if(A>0&&B>0)return A*B;}return 0;}"
    parse(source, "cpp")
    result = bind_arithmetic_operation(source, ["A", "B"], "*", language="cpp", integer_abi="ilp32")
    assert (result.type_status == "bound") is admitted, result
    source += "\nunsigned Wrap(void){return Read(2147483647,2147483647);}"
    reply = check_literal_calls(source, "Read", "check-overflow", "integer overflow in `A * B`", "ilp32", [2], language="cpp")
    if admitted:
        assert reply["status"] == "checked" and reply["calls"][0]["verdict"] == "violation"
    else:
        assert reply["status"] == "unavailable" and reply["calls"] == []
