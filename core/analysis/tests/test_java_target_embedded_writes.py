"""Stores evaluated inside Java assignment/update targets are definers."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import _get_parser, build_java_intraproc_cfg  # noqa: E402
from core.analysis.const_fold_java import JavaConstIndex, REFUSE, fold_expr_at  # noqa: E402
from core.analysis.dataflow import reaching_defs  # noqa: E402


def analyze(statement):
    source = ('class T { void m(String raw) {\n'
              'int[] arr=new int[1];\n'
              'String tmp="safe";\n' + statement + '\n'
              'System.out.println(tmp);\n} }')
    tree = _get_parser().parse(source.encode())
    assert not tree.root_node.has_error
    cfg = build_java_intraproc_cfg(source, "m")
    assert cfg is not None
    index = JavaConstIndex(source, (1, 6))
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
    store = next(node for node in cfg.nodes() if node.lineno == 4 and "arr" in node.defs)
    rd = reaching_defs(cfg)
    return store, rd.at(sink, "tmp"), fold_expr_at(rd, sink, reads[0], index)


def test_assignment_target_rebinding_invalidates_prior_constant():
    store, definers, value = analyze('arr[(tmp=raw).length()%1]=0;')
    assert value is REFUSE
    assert {"arr", "tmp"} <= store.defs
    assert store in definers


@pytest.mark.parametrize("statement", [
    'arr[(tmp=raw).length()%1]+=1;',
    'arr[(tmp=raw).length()%1]++;',
    '++arr[(tmp=raw).length()%1];',
])
def test_compound_and_update_target_rebindings_reach_later_reads(statement):
    store, definers, value = analyze(statement)
    assert value is REFUSE
    assert "tmp" in store.defs
    assert store in definers


def test_target_read_without_rebinding_keeps_unrelated_constant():
    store, _definers, value = analyze('arr[raw.length()%1]=0;')
    assert "tmp" not in store.defs
    assert value == "safe"
