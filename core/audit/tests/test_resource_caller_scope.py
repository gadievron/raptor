"""Caller-local bounds do not establish universal admission control."""
import pytest

from core.audit.resource_bounds import run_resource_bounds_check

pytest.importorskip("tree_sitter_c")


@pytest.mark.parametrize("bounded_first", [True, False])
def test_one_bounded_caller_cannot_refute_an_unbounded_sibling(tmp_path, bounded_first):
    inner = "void insert_fn(void)\n{\n    list_add(x, y);\n}\n"
    bounded = ("extern int g_session_count;\nvoid bounded(void)\n{\n"
               "    if (g_session_count >= 4) return;\n    insert_fn();\n}\n")
    unbounded = "void unbounded(void)\n{\n    insert_fn();\n}\n"
    entries = [("bounded.c", bounded), ("unbounded.c", unbounded)]
    if not bounded_first:
        entries.reverse()
    texts = {"inner.c": inner, **dict(entries)}
    for name, source in texts.items():
        (tmp_path / name).write_text(source)
    result = run_resource_bounds_check(
        tmp_path, "inner.c", "insert_fn", "the list grows without limit", source_texts=texts,
    )
    assert result.outcome == "inconclusive", result.reason
    assert "bound-in-caller" in result.reason
    assert result.bound_search["caller_bound_scope"] == "caller-local"
    assert result.bound_search["caller_bound_refutes_site"] is False
