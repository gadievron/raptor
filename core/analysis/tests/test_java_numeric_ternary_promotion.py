"""A chosen numeric ternary arm still undergoes conditional type conversion."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE, fold_expr  # noqa: E402


def fold(text):
    from core.analysis.cfg_builder_java import _get_parser

    tree = _get_parser().parse(f"class T {{ void m() {{ Object result = {text}; }} }}".encode())
    assert not tree.root_node.has_error
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == 'variable_declarator' and node.child_by_field_name('name').text == b'result':
            return fold_expr(node.child_by_field_name('value'), lambda *_: REFUSE)
        pending.extend(node.named_children)
    pytest.fail('missing fixture expression')


def test_unselected_floating_arm_cannot_leave_selected_value_as_integer():
    assert fold('String.valueOf(true ? 1 : 2.0).length()') is REFUSE


@pytest.mark.parametrize('text', [
    'false ? 2.0 : 1', 'true ? 1 : unknown',
    "true ? 97 : 'b'", "false ? 'b' : 97",
    'true ? 1 : 2.0f', 'true ? 1 : (false ? 2 : 3.0)',
])
def test_unmodelled_numeric_branch_conversions_refuse(text):
    assert fold(text) is REFUSE


@pytest.mark.parametrize('text,expected', [
    ('true ? 1 : 2', 1), ('false ? 1 : 2', 2),
    ('true ? (1 + 2) : 4', 3), ("true ? 'a' : 'b'", 'a'),
    ('true ? "safe" : unknown', 'safe'),
    ('false ? unknown : "safe"', 'safe'),
    ('true ? true : false', True),
])
def test_existing_same_numeric_kind_and_reference_branch_controls_remain(text, expected):
    assert fold(text) == expected


@pytest.mark.parametrize('ternary,length', [('true ? 1 : 2.0', 1), ("true ? 97 : 'b'", 2)],
                         ids=['float-promotion', 'char-narrowing'])
def test_actual_consumer_cannot_report_a_constant_sink_from_wrong_promoted_type(ternary, length):
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.const_fold_java import JavaConstIndex, all_definers_constant
    from core.analysis.dataflow import reaching_defs

    source = (
        'class T {\nvoid handle(String raw, java.io.PrintWriter w) {\n'
        f'String out = String.valueOf({ternary}).length() == {length} ? "safe" : raw;\n'
        'w.println(out);\n}\n}'
    )
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'w.println' in n.label)
    assert all_definers_constant(reaching_defs(cfg), sink, 'out',
                                JavaConstIndex(source, (1, 8)),
                                union_member_check=lambda _: True) is None
