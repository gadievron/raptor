"""Evaluated Java method receiver expressions contribute value uses."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import _get_parser, build_java_intraproc_cfg  # noqa: E402


def payload(expression):
    source = ('import java.util.Collections;\n'
              'class T { static class Holder { String value; }\n'
              'void m(String[] items, int index, Holder holder, boolean flag, String raw, String tmp) {\n'
              'Object result=' + expression + ';\n} }')
    assert not _get_parser().parse(source.encode()).root_node.has_error
    cfg = build_java_intraproc_cfg(source, "m")
    assert cfg is not None
    return next(node for node in cfg.nodes() if "result" in node.defs)


def test_array_receiver_evaluates_base_and_index():
    node = payload("items[index].trim()")
    assert {"items", "index"} <= node.uses
    assert "trim" not in node.uses


@pytest.mark.parametrize("expression,expected", [
    ("holder.value.trim()", {"holder"}),
    ("(tmp=raw).length()", {"raw"}),
    ("(flag ? raw : tmp).length()", {"flag", "raw", "tmp"}),
    ("((items[index])).trim()", {"items", "index"}),
])
def test_receiver_shapes_keep_evaluated_input_names(expression, expected):
    assert expected <= payload(expression).uses


def test_imported_static_class_remains_a_namespace():
    assert not payload("Collections.emptyList()").uses


def test_direct_local_receiver_still_contributes_its_value():
    assert payload("raw.trim()").uses == frozenset({"raw"})
