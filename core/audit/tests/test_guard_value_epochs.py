"""Control-path truth must not certify overwritten values at a later site."""
import pytest

from core.audit import resource_bounds as rb

pytest.importorskip("tree_sitter_c")


def _check(tmp_path, middle, *, before=""):
    source = ("void handle(int count, int input) {\n" + before +
              " if (count < 4) {\n" + middle + "  list_add(x, y);\n }\n}\n")
    (tmp_path / "owned.c").write_text(source)
    return rb.run_resource_bounds_check(tmp_path, "owned.c", "handle", "list grows without limit",
                                        source_texts={"owned.c": source})


@pytest.mark.parametrize("middle", ["  count = input;\n", "  count += input;\n",
                                      "  rewrite();\n", "  *alias = input;\n"],
                         ids=["assignment", "compound-store", "unknown-call", "indirect-store"])
def test_invalidated_value_cannot_supply_a_bound_receipt(tmp_path, middle):
    result = _check(tmp_path, middle)
    assert result.outcome == "inconclusive", result.reason
    assert rb.REASON_CENSUS_DEGRADED in result.reason


def test_unrelated_scalar_definition_does_not_invalidate_the_guard(tmp_path):
    result = _check(tmp_path, "  int unrelated = input;\n")
    assert result.outcome == "refuted", result.reason


def test_call_before_the_guard_does_not_invalidate_fresh_values(tmp_path):
    result = _check(tmp_path, "", before=" rewrite();\n")
    assert result.outcome == "refuted", result.reason


def test_side_effect_on_a_returning_sibling_path_is_irrelevant(tmp_path):
    result = _check(tmp_path, "  if (input) { rewrite(); return; }\n")
    assert result.outcome == "refuted", result.reason


def test_loop_retest_starts_a_fresh_value_epoch(tmp_path):
    source = "void handle(int count) {\n while (count < 4) {\n  list_add(x, y);\n  count++;\n }\n}\n"
    (tmp_path / "owned.c").write_text(source)
    result = rb.run_resource_bounds_check(tmp_path, "owned.c", "handle", "list grows without limit",
                                          source_texts={"owned.c": source})
    assert result.outcome == "refuted", result.reason


def test_epoch_budget_exhaustion_is_not_an_empty_guard_set(tmp_path, monkeypatch):
    from core.analysis import lifecycle_collector

    monkeypatch.setattr(lifecycle_collector, "_MAX_GUARD_EPOCH_VISITS", 0)
    result = _check(tmp_path, "  if (input) { rewrite(); return; }\n")
    assert result.outcome == "inconclusive", result.reason
    assert rb.REASON_CENSUS_DEGRADED in result.reason


def test_release_consumer_preserves_unknown_value_epochs():
    from core.audit.release_order import _guards_at

    source = "void handle(int status) {\n if (status) {\n  status = 0;\n  release();\n }\n}\n"
    assert _guards_at(source, "handle", 4, "owned.c", "c") is None


@pytest.mark.parametrize("body", ["  count = input;\n", ""], ids=["explicit-store", "opaque-site-effect"])
def test_inner_loop_cannot_reuse_an_outer_guard_epoch(tmp_path, body):
    result = _check(tmp_path, "  while (input) {\n   list_add(x, y);\n" + body + "  }\n")
    assert result.outcome == "inconclusive", result.reason


def test_acyclic_effect_after_the_site_does_not_change_entry_values(tmp_path):
    source = "void handle(int count, int input) {\n if (count < 4) {\n  list_add(x, y);\n  count = input;\n }\n}\n"
    (tmp_path / "owned.c").write_text(source)
    result = rb.run_resource_bounds_check(tmp_path, "owned.c", "handle", "list grows without limit",
                                          source_texts={"owned.c": source})
    assert result.outcome == "refuted", result.reason
