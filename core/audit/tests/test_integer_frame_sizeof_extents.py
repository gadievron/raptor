"""Array type extents inside sizeof can execute in C source prefixes."""

import pytest

from core.audit.integer_division import check_integer_division


def test_evaluated_sizeof_extent_cannot_preserve_the_entry_parameter_identity():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")
    source = (
        "unsigned Read(unsigned Value,unsigned Count){if(Count==1){"
        "(void)sizeof(int[++Count]);return Value/(Count-1);}return 0;}"
    )
    result = check_integer_division(
        source, "Potential zero divisor in `Value / (Count-1)`.",
        language="c", integer_abi="lp64",
    )
    # On the only admitted branch ++Count changes 1 to 2 before division,
    # so an entry Count==1 is not a witness for a zero denominator.
    assert result["violation"] is None and not result["witness_validated"], result


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("extent", ["4", "Count", "++Count", "next()"],
                         ids=["constant-array", "runtime-array", "mutating-extent", "call-extent"])
def test_shared_frame_refuses_sizeof_array_type_extents(language, extent):
    from core.audit.integer_conversion import _frame

    pytest.importorskip("tree_sitter_" + language)
    source = f"unsigned Read(unsigned Count){{(void)sizeof(int[{extent}]);return Count;}}"
    assert _frame(source, "lp64", language) is None


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("operand", ["unsigned", "Count", "++Count"],
                         ids=["builtin-type", "parameter", "unevaluated-update"])
def test_ordinary_sizeof_retains_a_current_entry_witness(language, operand):
    pytest.importorskip("tree_sitter_" + language)
    pytest.importorskip("z3")
    source = (
        "unsigned Read(unsigned Value,unsigned Count){if(Count==1){"
        f"(void)sizeof({operand});return Value/(Count-1);}}return 0;}}"
    )
    result = check_integer_division(
        source, "Potential zero divisor in `Value / (Count-1)`.",
        language=language, integer_abi="lp64",
    )
    assert result["violation"] is True and result["witness_validated"], result
    assert result["model"]["Count"] == 1 and result["denominator"] == 0
    assert result["proof_scope"] == "function-entry-source-model"
