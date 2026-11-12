"""Text-block map keys cannot use raw quoted-token slicing as their value."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE, fold_expr  # noqa: E402
from core.analysis.java_collection_index import (  # noqa: E402
    CollectionFoldResolver,
    build_local_collection_index,
)


def source_for(key):
    return (
        'import java.util.HashMap;\nclass T {\nvoid handle(String raw, java.io.PrintWriter w) {\n'
        'HashMap<String,String> m = new HashMap<>();\nm.put("key", "safe");\n'
        + 'm.put(' + key + ', raw);\nString result = m.get("key");\nw.println(result);\n}\n}'
    )


def index_and_expression(source):
    from core.analysis.cfg_builder_java import _get_parser

    tree = _get_parser().parse(source.encode())
    assert not tree.root_node.has_error
    index = build_local_collection_index(source, (1, source.count('\n') + 1))
    assert index is not None and index.ok
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == 'variable_declarator' and node.child_by_field_name('name').text == b'result':
            return index, node.child_by_field_name('value')
        pending.extend(node.named_children)
    pytest.fail('missing fixture expression')


def test_text_block_write_cannot_hide_a_raw_write_to_the_same_runtime_key():
    # Both spellings denote "key"; the text block has no final newline.
    source = source_for('"""\nkey"""')
    index, expression = index_and_expression(source)
    assert fold_expr(expression, lambda *_: REFUSE,
                     conduit_resolver=CollectionFoldResolver(index)) is REFUSE


@pytest.mark.parametrize('key', ['"""\nkey"""', '"""\n    key"""', '("""\nkey""")'])
def test_unsupported_text_block_keys_untrack_the_collection(key):
    index, _expression = index_and_expression(source_for(key))
    assert not index.tracked('m')


def test_plain_string_key_control_remains_constant_when_the_raw_key_differs():
    index, expression = index_and_expression(source_for('"other"'))
    assert index.tracked('m')
    assert fold_expr(expression, lambda *_: REFUSE,
                     conduit_resolver=CollectionFoldResolver(index)) == 'safe'


def test_ordinary_same_key_raw_write_still_refuses():
    index, expression = index_and_expression(source_for('"key"'))
    assert index.tracked('m')
    assert fold_expr(expression, lambda *_: REFUSE,
                     conduit_resolver=CollectionFoldResolver(index)) is REFUSE


def test_actual_constant_gate_cannot_select_the_stale_safe_map_value():
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.const_fold_java import JavaConstIndex, all_definers_constant
    from core.analysis.dataflow import reaching_defs

    source = source_for('"""\nkey"""')
    collection, _expression = index_and_expression(source)
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'w.println' in n.label)
    assert all_definers_constant(reaching_defs(cfg), sink, 'result',
                                JavaConstIndex(source, (1, source.count('\n') + 1)),
                                conduit_resolver=CollectionFoldResolver(collection),
                                union_member_check=lambda _: True) is None
