"""Java trim uses the inclusive U+0020 boundary, including ASCII controls."""

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
            return fold_expr(node.child_by_field_name("value"), lambda _name, _depth: REFUSE)
        pending.extend(node.named_children)
    pytest.fail("missing fixture expression")


def test_trim_control_cannot_select_the_wrong_length():
    assert fold('"' + chr(7) + 'a' + chr(7) + '".trim().length()') == 1


@pytest.mark.parametrize("code", [n for n in range(33) if n not in (0, 10, 13)])
def test_trim_removes_ascii_controls_only_at_edges(code):
    control = chr(code)
    assert fold('"' + control + 'a' + control + 'b' + control + '".trim()') == 'a' + control + 'b'


@pytest.mark.parametrize("text,expected", [
    ('" abc ".trim()', 'abc'), ('"".trim()', ''),
    ('"' + chr(127) + 'a' + chr(127) + '".trim()', chr(127) + 'a' + chr(127)),
])
def test_trim_preserves_existing_ascii_boundaries(text, expected):
    assert fold(text) == expected


@pytest.mark.parametrize("text", ['"é".trim()', '"a".trim(1)'])
def test_trim_does_not_admit_unicode_or_arguments(text):
    assert fold(text) is REFUSE


def test_raw_nul_is_outside_the_parser_accepted_fixture_domain():
    from core.analysis.cfg_builder_java import _get_parser

    source = b'class T { void m() { Object result = "\x00a\x00".trim(); } }'
    assert _get_parser().parse(source).root_node.has_error
