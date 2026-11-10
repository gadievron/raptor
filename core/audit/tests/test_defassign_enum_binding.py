"""Enum constants cannot share an outer parameter's SMT identity."""
import pytest

pytest.importorskip("tree_sitter_c")
pytest.importorskip("z3")

from core.audit import defassign as da


def _source(declaration):
    return ("int f(int a){int v; if(a > 0) v=1; {" + declaration
            + " if(a > 0) return v;} return 0;}")


@pytest.mark.parametrize("declaration", [
    "enum {a=1} object;", "enum inner {a=1} object;",
    "enum {other=0,a=1} object;",
], ids=["anonymous", "named", "later-enumerator"])
def test_enum_value_shadows_cannot_borrow_parameter_guard_identity(declaration):
    source = _source(declaration)
    assert "a" in da._assigned_names(da._parse_function(source))
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven, result.reason


@pytest.mark.parametrize("declaration", [
    "enum a {other=1} object;", "struct a {int field;} object;",
    "struct inner {int a;} object;", "enum {other=1} object;",
], ids=["enum-tag", "struct-tag", "member-name", "other-enumerator"])
def test_separate_namespaces_and_unrelated_constants_keep_the_guard_identity(declaration):
    source = _source(declaration)
    assert "a" not in da._assigned_names(da._parse_function(source))
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert result.proven and result.method == "structural+smt", result.reason


def test_bare_enum_statement_keeps_its_existing_refusal():
    source = _source("enum {a=1};")
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven
    assert "unsupported statement form: enum_specifier" in result.reason
