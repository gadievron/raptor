"""Only the selected upper-bound predicate can establish a local bound."""
import pytest

from core.audit import resource_bounds as rb

pytest.importorskip("tree_sitter_c")


@pytest.mark.parametrize("condition,outcome", [
    ("count < 4", "refuted"),
    ("count > 4", "confirmed"),
    ("count < 4 || ready", "inconclusive"),
    ("count < 4 + extra", "inconclusive"),
])
def test_bound_direction_and_whole_predicate(tmp_path, condition, outcome):
    source = f"void handle(int count) {{\n if ({condition}) {{\n list_add(x, y);\n }}\n}}\n"
    (tmp_path / "owned.c").write_text(source)
    result = rb.run_resource_bounds_check(tmp_path, "owned.c", "handle", "list grows without limit",
                                          source_texts={"owned.c": source})
    assert result.outcome == outcome, result.reason


@pytest.mark.parametrize("condition,outcome", [("count >= 4", "refuted"), ("count < 4", "confirmed")])
def test_early_return_preserves_false_arm_meaning(tmp_path, condition, outcome):
    source = f"void handle(int count) {{\n if ({condition}) return;\n list_add(x, y);\n}}\n"
    (tmp_path / "owned.c").write_text(source)
    result = rb.run_resource_bounds_check(tmp_path, "owned.c", "handle", "list grows without limit",
                                          source_texts={"owned.c": source})
    assert result.outcome == outcome, result.reason
