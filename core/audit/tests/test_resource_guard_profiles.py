"""Unsupported guard syntax is missing evidence, not an absent bound."""
import pytest

from core.audit import resource_bounds as rb

pytest.importorskip("tree_sitter_c")
pytest.importorskip("tree_sitter_cpp")


def _check(tmp_path, condition, language="c", prefix=""):
    source = prefix + f"void handle(int count, int q) {{\n if ({condition}) {{\n  list_add(x, y);\n }}\n}}\n"
    name = "owned.cpp" if language == "cpp" else "owned.c"
    (tmp_path / name).write_text(source)
    return rb.run_resource_bounds_check(tmp_path, name, "handle", "list grows without limit",
                                        source_texts={name: source})


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("condition", ["count < -1", "(count) < 4", "4 > count", "count < +4",
                                      "count < ~MASK", "count <= (4)", "count < q"],
                         ids=["negative-literal", "wrapped-operand", "numeric-left", "unary-plus",
                              "bitwise-bound", "wrapped-bound", "short-unknown-bound"])
def test_unsupported_comparison_is_not_a_no_bound_confirmation(tmp_path, language, condition):
    result = _check(tmp_path, condition, language)
    assert result.outcome == "inconclusive", result.reason
    assert rb.REASON_GUARD_UNDECIDED in result.reason


def test_short_resolved_constant_is_a_supported_bound(tmp_path):
    result = _check(tmp_path, "count < K", prefix="enum { K = 4 };\n")
    assert result.outcome == "refuted", result.reason
    assert result.bound_search["local"]["bound_source"] == "resolved-constant"


def test_supported_lower_bound_still_does_not_provide_an_upper_bound(tmp_path):
    result = _check(tmp_path, "count > 4")
    assert result.outcome == "confirmed", result.reason


def test_unsupported_constant_declaration_remains_undecided(tmp_path):
    result = _check(tmp_path, "count < K", prefix="static const int K = 4;\n")
    assert result.outcome == "inconclusive", result.reason
    assert rb.REASON_GUARD_UNDECIDED in result.reason
