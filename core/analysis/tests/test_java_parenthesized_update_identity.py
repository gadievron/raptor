"""Parenthesized scalar updates cannot borrow a same-line initializer."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import _get_parser, build_java_intraproc_cfg  # noqa: E402
from core.analysis.const_fold_java import JavaConstIndex, REFUSE, fold_expr_at  # noqa: E402
from core.analysis.dataflow import reaching_defs  # noqa: E402


def folded_after(statement):
    source = "class T { void m() { int n=0; " + statement + " System.out.println(n); } }"
    tree = _get_parser().parse(source.encode())
    assert not tree.root_node.has_error
    cfg = build_java_intraproc_cfg(source, "m")
    assert cfg is not None
    index = JavaConstIndex(source, (1, 1))
    assert index.ok
    pending = [tree.root_node]
    reads = []
    while pending:
        node = pending.pop()
        if node.type == "method_invocation" and node.child_by_field_name("name").text == b"println":
            reads.append(node.child_by_field_name("arguments").named_children[0])
        pending.extend(node.named_children)
    assert len(reads) == 1
    sink = next(node for node in cfg.nodes() if "System.out.println" in node.calls)
    return fold_expr_at(reaching_defs(cfg), sink, reads[0], index)


def test_postfix_parenthesized_update_cannot_fold_to_initializer():
    assert folded_after("(n)++;") is REFUSE


@pytest.mark.parametrize("statement", ["++(n);", "((n))--;", "--((n));", "n++;"])
def test_update_forms_refuse_instead_of_reusing_same_line_value(statement):
    assert folded_after(statement) is REFUSE


def test_parenthesized_read_preserves_unchanged_initializer():
    assert folded_after("int other=(n);") == 0
