"""Field member names are not locals, but receiver expressions have uses."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import _get_parser, build_java_intraproc_cfg  # noqa: E402


def payload(expression):
    source = ('import java.lang.System;\n'
              'class T { static class H { String value; }\n'
              'void m(H[] holders,int index,H holder,H other,boolean flag) {\n'
              'Object result=' + expression + ';\n} }')
    assert not _get_parser().parse(source.encode()).root_node.has_error
    cfg = build_java_intraproc_cfg(source, "m")
    assert cfg is not None
    return next(node for node in cfg.nodes() if "result" in node.defs)


def test_field_receiver_preserves_array_index_read():
    node = payload("holders[index].value")
    assert {"holders", "index"} <= node.uses
    assert "value" not in node.uses


@pytest.mark.parametrize("expression,expected", [
    ("(holder=other).value", {"other"}),
    ("(flag ? holder : other).value", {"flag", "holder", "other"}),
    ("((holders[index])).value", {"holders", "index"}),
])
def test_computed_field_receiver_keeps_evaluated_inputs(expression, expected):
    node = payload(expression)
    assert expected <= node.uses
    assert "value" not in node.uses


def test_direct_field_base_keeps_existing_local_use():
    assert payload("holder.value").uses == frozenset({"holder"})


def test_imported_static_field_base_is_still_a_namespace():
    assert not payload("System.out").uses
