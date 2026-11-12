"""Default-locale Java case conversion cannot supply locale-sensitive values."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE, fold_expr  # noqa: E402


def expression(text):
    from core.analysis.cfg_builder_java import _get_parser

    tree = _get_parser().parse(f"class T {{ void m() {{ Object result = {text}; }} }}".encode())
    assert not tree.root_node.has_error
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "variable_declarator" and node.child_by_field_name("name").text == b"result":
            return node.child_by_field_name("value")
        pending.extend(node.named_children)
    pytest.fail("missing fixture expression")


def fold(text):
    return fold_expr(expression(text), lambda _name, _depth: REFUSE)


def test_default_locale_ascii_i_cannot_select_a_fixed_branch():
    # JDK String docs: Turkish lower-case I is U+0131, unlike ROOT/English i.
    # The target's default locale is not an input to this folder.
    assert fold('"I".toLowerCase().charAt(0) == \'i\'') is REFUSE


@pytest.mark.parametrize("text", [
    '"I".toLowerCase()', '"TITLE".toLowerCase()', '"i".toUpperCase()',
    '"title".toUpperCase()', '"MiXeD".toUpperCase()',
    '"I".toLowerCase().charAt(0)', '"i".toUpperCase().charAt(0)',
    '"I".toLowerCase().substring(0, 1)',
], ids=["lower-i", "lower-word", "upper-i", "upper-word", "old-upper-fixture",
        "lower-char", "upper-char", "composed-substring"])
def test_default_locale_sensitive_values_refuse_before_further_folding(text):
    assert fold(text) is REFUSE


@pytest.mark.parametrize("text,expected", [
    ('"i".toLowerCase()', "i"), ('"I".toUpperCase()', "I"),
    ('"MIXED".toUpperCase()', "MIXED"), ('"mixed".toLowerCase()', "mixed"),
    ('"ABCxyz".toLowerCase()', "abcxyz"), ('"ABCxyz".toUpperCase()', "ABCXYZ"),
    ('"".toLowerCase()', ""), ('"".toUpperCase()', ""),
])
def test_existing_locale_invariant_ascii_subset_stays_available(text, expected):
    assert fold(text) == expected


@pytest.mark.parametrize("text", [
    '"Ä".toLowerCase()', '"é".toUpperCase()',
    '"I".toLowerCase(java.util.Locale.ROOT)',
])
def test_non_ascii_and_explicit_locale_overloads_are_not_newly_admitted(text):
    assert fold(text) is REFUSE


@pytest.mark.parametrize("condition", [
    '"I".toLowerCase().charAt(0) == \'i\'',
    '"i".toUpperCase().charAt(0) == \'I\'',
])
def test_unknown_locale_cannot_prune_a_live_dataflow_branch(condition):
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg

    source = (
        "class T { void handle(String raw, java.io.PrintWriter w) {"
        f"if ({condition}) {{ w.println(\"safe\"); }} else {{ w.println(raw); }}"
        "} }"
    )
    cfg = build_java_intraproc_cfg(source, "handle")
    assert cfg is not None
    assert "if:constant-resolved" not in cfg.build_notes
