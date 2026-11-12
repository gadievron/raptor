"""Tracked collection semantics require an unshadowed java.util constructor."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE, fold_expr  # noqa: E402
from core.analysis.java_collection_index import (  # noqa: E402
    CollectionFoldResolver,
    build_local_collection_index,
)

_CUSTOM = '''static class HashMap<K,V> {
V first;
void put(K key,V value) { if (first == null) first = value; }
V get(K key) { return first; }
}
'''


def source_for(type_name='HashMap', imports='', custom=''):
    return (
        imports + '\nclass T {\n' + custom
        + '\nvoid handle(String raw, java.io.PrintWriter w) {\n'
        + type_name + '<String,String> m = new ' + type_name + '<>();\n'
        'm.put("attacker", raw);\nm.put("key", "safe");\n'
        'String result = m.get("key");\nw.println(result);\n}\n}'
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


def test_source_defined_hashmap_cannot_borrow_jdk_map_semantics():
    index, expression = index_and_expression(source_for(custom=_CUSTOM))
    assert fold_expr(expression, lambda *_: REFUSE,
                     conduit_resolver=CollectionFoldResolver(index)) is REFUSE


def test_member_type_shadow_of_explicit_import_still_refuses():
    index, _expression = index_and_expression(source_for(
        imports='import java.util.HashMap;', custom=_CUSTOM))
    assert not index.tracked('m')


@pytest.mark.parametrize('type_name,imports', [
    ('HashMap', ''), ('HashMap', 'import java.util.*;'),
    ('HashMap', 'import other.HashMap;'), ('other.HashMap', ''),
])
def test_unresolved_or_non_jdk_constructor_identity_refuses(type_name, imports):
    index, _expression = index_and_expression(source_for(type_name, imports))
    assert not index.tracked('m')


@pytest.mark.parametrize('type_name,imports,custom', [
    ('HashMap', 'import java.util.HashMap;', ''),
    ('java.util.HashMap', '', ''),
    ('java.util.HashMap', '', _CUSTOM),
])
def test_explicit_jdk_identity_keeps_existing_constant_control(type_name, imports, custom):
    index, expression = index_and_expression(source_for(type_name, imports, custom))
    assert index.tracked('m')
    assert fold_expr(expression, lambda *_: REFUSE,
                     conduit_resolver=CollectionFoldResolver(index)) == 'safe'


def test_actual_constant_gate_cannot_trust_the_lookalike_map():
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.const_fold_java import JavaConstIndex, all_definers_constant
    from core.analysis.dataflow import reaching_defs

    source = source_for(custom=_CUSTOM)
    collection, _expression = index_and_expression(source)
    cfg = build_java_intraproc_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'w.println' in n.label)
    assert all_definers_constant(reaching_defs(cfg), sink, 'result',
                                JavaConstIndex(source, (1, source.count('\n') + 1)),
                                conduit_resolver=CollectionFoldResolver(collection),
                                union_member_check=lambda _: True) is None


def test_qualified_spelling_with_source_defined_java_head_refuses():
    nested = 'static class java { static class util {\n' + _CUSTOM + '\n} }'
    source = source_for('java.util.HashMap', custom=nested)
    source = ('import java.io.PrintWriter;\n'
              + source.replace('java.io.PrintWriter w', 'PrintWriter w'))
    index, _expression = index_and_expression(source)
    assert not index.tracked('m')


def test_enclosing_instance_creation_refuses():
    owner = 'static class Owner {\n' + _CUSTOM.replace('static class HashMap', 'class HashMap') + '\n}'
    source = source_for('Owner.HashMap', imports='import java.util.HashMap;', custom=owner)
    source = source.replace('java.io.PrintWriter w)', 'java.io.PrintWriter w, Owner owner)')
    source = source.replace('new Owner.HashMap<>()', 'owner.new HashMap<>()')
    index, _expression = index_and_expression(source)
    assert not index.tracked('m')
