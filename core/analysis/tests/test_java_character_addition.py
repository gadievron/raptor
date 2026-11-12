"""Character literal addition must not become String concatenation."""

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
        if node.type == "variable_declarator" and node.child_by_field_name("name").text == b"result":
            return fold_expr(node.child_by_field_name("value"), lambda *_: REFUSE)
        pending.extend(node.named_children)
    pytest.fail("missing fixture expression")


def test_character_addition_cannot_choose_a_string_length():
    # Java promotes the characters to int: 97 + 98 = 195, string length 3.
    # Numeric char promotion is outside this folder's supported operations.
    assert fold("String.valueOf('a' + 'b').length()") is REFUSE


@pytest.mark.parametrize("text", [
    "'a' + 'b'", "('a') + ('b')", "(('a')) + 'b'",
    "String.valueOf('a' + 'b').length() == 2",
    "String.valueOf('a' + 'b').length() == 2 ? 1 : 0",
])
def test_literal_numeric_addition_refuses_before_value_consumption(text):
    assert fold(text) is REFUSE


@pytest.mark.parametrize("text,expected", [
    ('"a" + "b"', 'ab'), ('"a" + \'b\'', 'ab'),
    ('\'a\' + "b"', 'ab'), ("'a' == 'a'", True),
    ("'a' == 'b'", False), ("String.valueOf('a')", 'a'),
    ('String.valueOf(97 + 98).length()', 3),
])
def test_string_concatenation_and_existing_character_operations_remain(text, expected):
    assert fold(text) == expected
