"""A target ABI does not establish attributed parameter types."""
import pytest

pytest.importorskip("tree_sitter_c")
pytest.importorskip("z3")

from core.audit import defassign as da


@pytest.mark.parametrize("parameter", [
    "unsigned a __attribute__((mode(HI)))",
    "unsigned __attribute__((mode(HI))) a",
], ids=["trailing-mode", "type-mode"])
def test_mode_attributes_cannot_borrow_the_builtin_unsigned_profile(parameter):
    # An unsigned 16-bit mode can promote to signed int under ILP32;
    # a=0 then admits the unassigned path. Ordinary unsigned-int
    # subtraction, in contrast, makes the guard a tautology.
    source = f"int f({parameter}){{int v; if(a - 1 >= 0) v=1; return v;}}"
    node = da._parse_function(source)
    assert da._parameter_int_types(node, "ilp32") == {}
    result = da.check_definite_assignment(source, "v", integer_abi="ilp32")
    assert not result.proven, result.reason


@pytest.mark.parametrize("attribute", ["unused", "aligned(16)", "mode(HI)"])
def test_attributes_require_their_own_admission_even_for_repeated_guards(attribute):
    source = (f"int f(int a __attribute__(({attribute}))){{int v; "
              "if(a > 5) v=1; if(a > 5) return v; return 0;}")
    assert da._parameter_int_types(da._parse_function(source), "lp64") == {}
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven, result.reason


@pytest.mark.parametrize("parameter", ["unsigned a", "const unsigned a"])
def test_builtin_parameter_structure_retains_its_explicit_profile(parameter):
    source = f"int f({parameter}){{int v; if(a >= 0) v=1; return v;}}"
    result = da.check_definite_assignment(source, "v", integer_abi="ilp32")
    assert result.proven and result.method == "structural+smt", result.reason


def test_structural_assignment_does_not_need_attribute_type_semantics():
    source = "int f(unsigned a __attribute__((mode(HI)))){int v=1; return v;}"
    result = da.check_definite_assignment(source, "v")
    assert result.proven and result.method == "structural", result.reason


@pytest.mark.parametrize("parameter", ["unsigned a", "const unsigned a", "register unsigned a"])
def test_arithmetic_guard_keeps_the_selected_profile_refusal(parameter):
    source = f"int f({parameter}){{int v; if(a - 1 >= 0) v=1; return v;}}"
    result = da.check_definite_assignment(source, "v", integer_abi="ilp32")
    assert not result.proven, result.reason


def test_storage_specifier_keeps_the_selected_parameter_refusal():
    source = "int f(register unsigned a){int v; if(a >= 0) v=1; return v;}"
    assert da._parameter_int_types(da._parse_function(source), "ilp32") == {}
    result = da.check_definite_assignment(source, "v", integer_abi="ilp32")
    assert not result.proven, result.reason
