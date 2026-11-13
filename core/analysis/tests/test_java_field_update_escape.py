"""Field increment/decrement are stores under the Java escape contract."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import _get_parser, build_java_intraproc_cfg  # noqa: E402


def statement_node(statement):
    source = ('class T { static class H { int count; }\n'
              'void m(H holder) { int count=0; int[] values=new int[1];\n'
              + statement + '\n} }')
    assert not _get_parser().parse(source.encode()).root_node.has_error
    cfg = build_java_intraproc_cfg(source, "m")
    assert cfg is not None
    return next(node for node in cfg.nodes() if node.label == statement)


def test_postfix_field_update_is_an_escaping_store():
    assert statement_node("holder.count++;").may_escape is True


@pytest.mark.parametrize("statement", [
    "++holder.count;", "holder.count--;", "--holder.count;",
    "(holder.count)++;", "++((holder.count));", "holder.count=1;",
])
def test_field_store_spellings_share_the_escape_stamp(statement):
    assert statement_node(statement).may_escape is True


def test_local_scalar_update_still_has_no_structural_escape():
    node = statement_node("count++;")
    assert node.defs == frozenset({"count"})
    assert node.may_escape is False


def test_array_update_retains_existing_escape_stamp():
    assert statement_node("values[0]++;").may_escape is True


def test_field_read_is_not_a_field_store():
    assert statement_node("int copy=holder.count;").may_escape is False
