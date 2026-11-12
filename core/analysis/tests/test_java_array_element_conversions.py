"""Array elements need conversion checks as well as aliasing qualification."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE, fold_expr  # noqa: E402
from core.analysis.value_set_java import build_table_resolver  # noqa: E402


def fold(declaration, expression):
    from core.analysis.cfg_builder_java import _get_parser

    source = 'class T { void m() { ' + declaration + ' Object result = ' + expression + '; } }'
    tree = _get_parser().parse(source.encode())
    assert not tree.root_node.has_error
    resolver = build_table_resolver(source, (1, 1))
    assert resolver is not None
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == 'variable_declarator' and node.child_by_field_name('name').text == b'result':
            return fold_expr(node.child_by_field_name('value'), lambda *_: REFUSE,
                             array_resolver=resolver)
        pending.extend(node.named_children)
    pytest.fail('missing fixture expression')


def test_character_array_integer_initializer_cannot_keep_integer_string_value():
    assert fold('char[] values = {97};', 'String.valueOf(values[0]).length()') is REFUSE


@pytest.mark.parametrize('declaration,expression', [
    ('char values[] = {97};', 'String.valueOf(values[0]).length()'),
    ('var values = new char[]{97};', 'String.valueOf(values[0]).length()'),
    ('float[] values = {1};', 'values[0] / 2 == 0'),
    ('double[] values = {1};', 'values[0] / 2 == 0'),
    ("int[] values = {'a'};", 'String.valueOf(values[0]).length()'),
    ("long[] values = {'a'};", 'String.valueOf(values[0]).length()'),
    ('Character[] values = {97};', 'String.valueOf(values[0]).length()'),
    ("Short[] values = {'a'};", 'String.valueOf(values[0]).length()'),
    ("java.lang.Byte[] values = {'a'};", 'String.valueOf(values[0]).length()'),
    ('Object[] values = new Character[]{97};', 'String.valueOf(values[0]).length()'),
])
def test_unmodelled_element_conversions_refuse(declaration, expression):
    assert fold(declaration, expression) is REFUSE


@pytest.mark.parametrize('declaration,expression,expected', [
    ('String[] values = {"safe"};', 'values[0]', 'safe'),
    ('int[] values = {97};', 'String.valueOf(values[0]).length()', 2),
    ('long[] values = {97};', 'String.valueOf(values[0]).length()', 2),
    ("char[] values = {'a'};", 'String.valueOf(values[0]).length()', 1),
    ('boolean[] values = {true};', 'values[0]', True),
    ('Byte[] values = {97};', 'String.valueOf(values[0]).length()', 2),
    ('Short[] values = {97};', 'String.valueOf(values[0]).length()', 2),
])
def test_existing_identity_element_controls_remain(declaration, expression, expected):
    assert fold(declaration, expression) == expected


def test_array_conversion_cannot_prune_the_live_raw_branch():
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg

    source = '''class T {
void handle(String raw, java.io.PrintWriter w) {
char[] values = {97};
if (String.valueOf(values[0]).length() == 2) { w.println("safe"); }
else { w.println(raw); }
}
}'''
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    assert 'if:constant-resolved' not in cfg.build_notes
    raw_sink = next(n for n in cfg.nodes() if 'w.println(raw)' in n.label)
    pending = [cfg.entry]
    seen = set()
    while pending:
        node = pending.pop()
        if node not in seen:
            seen.add(node)
            pending.extend(cfg.successors(node))
    assert raw_sink in seen


def test_boxed_byte_array_cannot_keep_character_string_value():
    assert fold("Byte[] values = {'a'};", 'String.valueOf(values[0]).length()') is REFUSE
