"""SMT parameter types belong to the enclosing function's formal scope."""
import pytest

pytest.importorskip("tree_sitter_c")
pytest.importorskip("z3")

from core.audit import defassign as da


@pytest.mark.parametrize("prototype", [
    "int g(unsigned a);",
    "int (*g)(unsigned a);",
], ids=["function-prototype", "function-pointer-prototype"])
def test_body_prototype_cannot_replace_outer_parameter_type(prototype):
    source = f"int f(int a){{int v; {prototype} if(a >= 0) v=1; return v;}}"
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven, result.reason
    node = da._parse_function(source)
    assert da._parameter_int_types(node, "lp64") == {"a": (True, 32)}


def test_callback_prototype_cannot_replace_sibling_parameter_type():
    source = "int f(int a, int (*callback)(unsigned a)){int v; if(a >= 0) v=1; return v;}"
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven, result.reason
    assert da._parameter_int_types(da._parse_function(source), "lp64") == {"a": (True, 32)}


def test_shadowed_guard_parameters_cannot_share_a_scalar_epoch():
    source = "int f(int a){int v; if(a >= 0) v=1; {int a=1; if(a >= 0) return v;} return 0;}"
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven, result.reason
    assert da._parameter_int_types(da._parse_function(source), "lp64") == {}


def test_callback_parameter_is_not_a_local_variables_formal_declaration():
    source = "int f(int (*callback)(int v)){int v=1; return v;}"
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert result.proven and result.method == "structural", result.reason
    declarations = da._find_variable_decls(da._parse_function(source), "v")
    assert len(declarations) == 1 and not declarations[0].is_parameter


def test_unrelated_prototype_preserves_a_real_parameter_contradiction():
    source = "int f(int a){int v; int g(unsigned a); if(a > 5) v=1; if(a > 5) return v; return 0;}"
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert result.proven and result.method == "structural+smt", result.reason
    assert result.smt_paths_discharged >= 1


def test_actual_unsigned_formal_type_remains_available():
    source = "int f(unsigned a){int v; int g(int a); if(a >= 0) v=1; return v;}"
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert result.proven and result.method == "structural+smt", result.reason
    assert da._parameter_int_types(da._parse_function(source), "lp64") == {"a": (False, 32)}


def test_returned_function_pointer_parameters_do_not_supply_guard_types():
    source = "int (*f(int a))(unsigned a){int v; if(a >= 0) v=1; consume(v); return 0;}"
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven, result.reason
    assert da._parameter_int_types(da._parse_function(source), "lp64") == {"a": (True, 32)}


def test_candidate_helpers_exclude_nested_prototype_parameters():
    source = "int (*f(int a, int (*callback)(int nested)))(unsigned returned){int v=1; int g(int body); return 0;}"
    assert da.function_parameter_names(source) == frozenset({"a", "callback"})
    local_names, parameters = da.function_scope_names(source)
    assert parameters == frozenset({"a", "callback"})
    assert not {"nested", "returned", "body"} & local_names
    assert "v" in local_names


def test_block_function_name_cannot_borrow_an_outer_scalar_identity():
    source = "int f(int a){int v; if(a != 0) v=1; {int a(void); if(a != 0) return v;} return 0;}"
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven, result.reason
    assert "a" in da._assigned_names(da._parse_function(source))
