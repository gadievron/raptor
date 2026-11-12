"""Computed Java character values retain their numeric-addition boundary."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE, fold_expr  # noqa: E402


def fold(text, names=None):
    from core.analysis.cfg_builder_java import _get_parser

    tree = _get_parser().parse(f"class T {{ void m() {{ Object result = {text}; }} }}".encode())
    assert not tree.root_node.has_error
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "variable_declarator" and node.child_by_field_name("name").text == b"result":
            return fold_expr(node.child_by_field_name("value"), lambda name, _depth: (names or {}).get(name, REFUSE))
        pending.extend(node.named_children)
    pytest.fail("missing fixture expression")


def test_computed_characters_cannot_become_a_concatenated_string():
    assert fold('String.valueOf("a".charAt(0) + "b".charAt(0)).length()') is REFUSE


@pytest.mark.parametrize("text", [
    '"a".charAt(0) + \'b\'', '\'a\' + "b".charAt(0)',
    '(true ? \'a\' : \'b\') + \'c\'',
])
def test_character_identity_survives_composition(text):
    assert fold(text) is REFUSE


def test_character_identity_survives_existing_name_resolver():
    values = {'left': fold("'a'"), 'right': fold('"b".charAt(0)')}
    assert fold('left + right', values) is REFUSE


@pytest.mark.parametrize("text,expected", [
    ('"a".charAt(0) + "b"', 'ab'),
    ('"a" + "b".charAt(0)', 'ab'),
    ('String.valueOf("a".charAt(0)) + "b".charAt(0)', 'ab'),
    ('String.valueOf(\'a\') + \'b\'', 'ab'),
    ('"a".charAt(0) == \'a\'', True),
    ('"a".charAt(0) != \'b\'', True),
])
def test_actual_string_conversions_and_character_comparisons_still_fold(text, expected):
    assert fold(text) == expected


def test_character_addition_cannot_make_the_sink_argument_constant():
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.const_fold_java import JavaConstIndex, all_definers_constant
    from core.analysis.dataflow import reaching_defs

    source = '''class T {
    void handle(String raw, java.io.PrintWriter w) {
        char left = 'a';
        char right = "b".charAt(0);
        String out = String.valueOf(left + right).length() == 2 ? "safe" : raw;
        w.println(out);
    }
}'''
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'w.println' in n.label)
    index = JavaConstIndex(source, (1, source.count('\n') + 1))
    assert all_definers_constant(reaching_defs(cfg), sink, 'out', index,
                                union_member_check=lambda _values: True) is None
