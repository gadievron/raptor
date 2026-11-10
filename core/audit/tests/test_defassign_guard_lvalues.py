"""Grouped scalar writes and escapes invalidate repeated guard identities."""
import pytest

pytest.importorskip("tree_sitter_c")
pytest.importorskip("z3")

from core.audit import defassign as da


def _source(operation):
    return ("int f(int a, int b, int *buf){int v; if(a > 5) v=1; "
            + operation + " if(a > 5) return v; return 0;}")


@pytest.mark.parametrize("operation", [
    "reset(&(a));", "reset(&((/* same scalar */ a)));", "(a) = 10;",
    "((a)) += 10;", "++(a);", "((a))++;",
    "a=10;", "reset(&a);",
], ids=["address", "commented-address", "assignment", "compound-assignment",
        "prefix-update", "postfix-update", "plain-assignment", "plain-address"])
def test_grouping_cannot_hide_guard_parameter_mutation(operation):
    source = _source(operation)
    assert "a" in da._assigned_names(da._parse_function(source))
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven, result.reason


@pytest.mark.parametrize("operation", [
    "reset(&(b));", "(b)=10;", "((b)) += 10;", "++(b);", "buf[a]=10;",
], ids=["other-address", "other-assignment", "other-compound", "other-update", "array-element"])
def test_unrelated_lvalues_do_not_invalidate_the_guard_parameter(operation):
    source = _source(operation)
    assert "a" not in da._assigned_names(da._parse_function(source))
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert result.proven and result.method == "structural+smt", result.reason
