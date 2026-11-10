"""Condition evaluation alone does not establish a truth-edge premise."""
import pytest

from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
from core.analysis.dominators import build_dom_tree
from core.analysis.lifecycle_collector import collect_guards_at_site

pytest.importorskip("tree_sitter_c")


def test_reconverged_if_condition_is_not_a_later_site_guard():
    source = """void handle(int count, int flag)
{
    if (count < 4) {
        record();
    }
    if (flag) {
        consume();
    }
}
"""
    cfg = build_cpp_intraproc_cfg(source, "handle", language="c")
    assert cfg is not None
    line = next(i for i, text in enumerate(source.splitlines(), 1) if "consume();" in text)
    guards = collect_guards_at_site(cfg, build_dom_tree(cfg), line, "owned.c")
    assert {guard.condition for guard in guards} == {"flag"}


def _guards(source, marker, language="c"):
    cfg = build_cpp_intraproc_cfg(source, "handle", language=language)
    assert cfg is not None
    line = next(i for i, text in enumerate(source.splitlines(), 1) if marker in text)
    return collect_guards_at_site(cfg, build_dom_tree(cfg), line, "owned.c")


def test_false_arm_preserves_polarity():
    source = "void handle(int count) {\n if (count >= 4) return;\n consume();\n}\n"
    guard, = _guards(source, "consume();")
    assert guard.condition == "count >= 4"
    assert guard.polarity is False


@pytest.mark.parametrize("loop", ["while (count < 4)", "for (; count < 4;)"])
def test_break_does_not_mint_a_false_loop_exit_guard(loop):
    source = f"void handle(int count) {{\n {loop} {{\n  if (ready) break;\n  record();\n }}\n consume();\n}}\n"
    assert not _guards(source, "consume();")


def test_do_body_does_not_require_tail_condition():
    source = "void handle(int count) {\n do {\n  consume();\n } while (count < 4);\n}\n"
    assert not _guards(source, "consume();")


def test_empty_arm_reconvergence_does_not_supply_a_guard():
    source = "void handle(int flag) {\n if (flag) {} else {}\n consume();\n}\n"
    assert not _guards(source, "consume();")


def test_goto_can_bypass_the_branch_entry():
    source = "void handle(int flag) {\n goto target;\n if (flag) {\ntarget: consume();\n }\n}\n"
    assert not _guards(source, "target:")


def test_branch_fact_keeps_full_condition_beyond_display_label():
    name = "long_count_" + "x" * 80
    source = f"void handle(int {name}) {{\n if ({name} < 4) {{\n consume();\n }}\n}}\n"
    guard, = _guards(source, "consume();")
    assert guard.condition == f"{name} < 4"


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_explicit_arms_have_opposite_polarities(language):
    source = "void handle(int flag) {\n if (flag) {\n left();\n } else {\n right();\n }\n}\n"
    left, = _guards(source, "left();", language)
    right, = _guards(source, "right();", language)
    assert (left.condition, left.polarity) == ("flag", True)
    assert (right.condition, right.polarity) == ("flag", False)


def test_for_operand_parentheses_are_not_stripped_as_an_outer_pair():
    source = "void handle(int count, int bound) {\n for (; (count) < (bound);) {\n consume();\n }\n}\n"
    guard, = _guards(source, "consume();")
    assert guard.condition == "(count) < (bound)"


def test_line_projection_retains_native_branch_polarity():
    from core.analysis.cfg_conditions import extract_conditions_from_cfg

    source = "void handle(int flag) {\n if (flag) {\n left();\n } else {\n right();\n }\n}\n"
    cfg = build_cpp_intraproc_cfg(source, "handle", language="c")
    assert cfg is not None
    edges = [edge for edge in extract_conditions_from_cfg(cfg) if edge.condition is not None]
    assert {(edge.dst_line, edge.condition.polarity) for edge in edges} == {(3, True), (5, False)}


@pytest.mark.parametrize("loop", ["while (count < 4)", "for (; count < 4;)"])
def test_normal_loop_exit_preserves_false_polarity(loop):
    source = f"void handle(int count) {{\n {loop} {{\n  record();\n }}\n consume();\n}}\n"
    guard, = _guards(source, "consume();")
    assert (guard.condition, guard.polarity) == ("count < 4", False)


def test_do_break_does_not_establish_tail_condition():
    source = "void handle(int count) {\n do {\n  if (ready) break;\n  record();\n } while (count < 4);\n consume();\n}\n"
    assert not _guards(source, "consume();")
