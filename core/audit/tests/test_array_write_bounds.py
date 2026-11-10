"""Zero stores require their own source access and defined-prefix proof."""

import pytest

from core.audit import array_bounds as bounds

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")
pytest.importorskip("z3")

CLAIM = "Potential out-of-bounds write at `Data[Index]`."
SOURCE = "int Write(int Index) { int Data[4]={0}; if(Index >= 0 && Index <= 4) { Data[Index] = 0; } return 0; }"


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_zero_store_has_independently_replayed_boundary_witness(language):
    pytest.importorskip("tree_sitter_cpp" if language == "cpp" else "tree_sitter_c")
    result = bounds.check_array_bounds(SOURCE, CLAIM, language=language, integer_abi="lp64")
    assert result["violation"] is True, result
    assert result["access_kind"] == "write"
    assert result["witness_index"] == result["model"]["Index"] == 4
    safe = bounds.check_array_bounds(SOURCE.replace("Index <= 4", "Index < 4"), CLAIM,
                                     language=language, integer_abi="lp64")
    assert safe["violation"] is False
    assert "model" not in safe


@pytest.mark.parametrize("source,claim", [
    (SOURCE, CLAIM.replace("write", "read")),
    (SOURCE.replace("Data[Index] = 0;", "return Data[Index];"), CLAIM),
    (SOURCE.replace("= 0; }", "= 1; }"), CLAIM),
    (SOURCE.replace("Data[Index] = 0", "Data[Index] += 0"), CLAIM),
    (SOURCE.replace("Data[Index] = 0", "Data[Index+1] = 0"), CLAIM.replace("[Index]", "[Index+1]")),
    (SOURCE.replace("Data[Index] = 0", "Index = 4; Data[Index] = 0"), CLAIM),
    (SOURCE.replace("int Data[4]", "const int Data[4]"), CLAIM),
    (SOURCE.replace("int Data[4]", "volatile int Data[4]"), CLAIM),
    (SOURCE.replace("int Data[4]={0};", "int *Data;"), CLAIM),
    (SOURCE.replace("Data[Index] = 0", "return (Data[Index] = 0)"), CLAIM),
    (SOURCE.replace("Data[Index] = 0", "Data[Index] = call()"), CLAIM),
    (SOURCE.replace("Data[Index] = 0", "Data[Index] = 0; Data[0] = 0"), CLAIM),
    (SOURCE, "No out-of-bounds write at `Data[Index]`."),
])
def test_unsupported_or_mismatched_store_does_not_earn_a_witness(source, claim):
    result = bounds.check_array_bounds(source, claim, language="c", integer_abi="lp64")
    assert result["violation"] is None, result
    assert "model" not in result


def test_store_keeps_reaching_entry_and_prefix_obligations():
    impossible = SOURCE.replace("Index <= 4", "Index < 0")
    result = bounds.check_array_bounds(impossible, CLAIM, language="c", integer_abi="lp64")
    assert result["violation"] is None and result["entry_feasible"] is False
    unsafe_prefix = SOURCE.replace("int Data[4]={0};", "int Data[4]={0}; int Prior = Index + 1;")
    result = bounds.check_array_bounds(unsafe_prefix, CLAIM, language="c", integer_abi="lp64")
    assert result["violation"] is None and "model" not in result


def test_old_read_claim_and_bare_access_remain_read_only():
    assert bounds.parse_array_access_claim(CLAIM) is None
    assert not bounds.has_array_read_goal(CLAIM)
    assert not bounds.has_array_write_goal("Data[Index]")
    assert not bounds.has_array_write_goal("out-of-bounds write at Data[Index]")
    assert bounds.has_array_write_goal(CLAIM)
    assert bounds.check_array_bounds(SOURCE, "Data[Index]", language="c", integer_abi="lp64")["violation"] is None
