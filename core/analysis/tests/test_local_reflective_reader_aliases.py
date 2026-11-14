"""Fixed owned nested getter frame-effect probe; no external source execution."""
import ast
import html

import pytest
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _detect_summary_unknown, build_taint_summaries
SOURCE = 'import sys\nimport html\nobserved = []\nclass Witness:\n    @property\n    def value(self):\n        current = sys._getframe()\n        try:\n            for _ in range(8):\n                if current is None:\n                    break\n                if current.f_code is helper.__code__:\n                    observed.append("owned-helper")\n                    return current.f_locals["raw"]\n                current = current.f_back\n            raise AssertionError("owned helper frame not present")\n        finally:\n            del current\nwitness = Witness()\ndef helper(raw):\n    def nested():\n        read_attribute = getattr\n        return read_attribute(witness, "value")\n    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)\n'
class Marker(str):
    pass

def test_local_getter_alias_cannot_forge_clean_path():
    assert not any(isinstance(n, ast.Attribute) and n.attr in {"__annotations__", "__annotate__"} for n in ast.walk(ast.parse(SOURCE)))
    graph = build_python_module_callgraph(SOURCE)
    assert graph is not None
    summaries = build_taint_summaries(graph, SOURCE)
    namespace = {"__name__": "owned_nested_getter_fixture"}
    exec(compile(SOURCE, "<owned-nested-getter>", "exec", dont_inherit=True), namespace)
    marker = Marker("<owned-getter-marker>")
    assert namespace["helper"](marker) is marker
    assert str(marker) in namespace["handle"](marker)
    assert html.escape(marker) != marker
    clean = _param_cleanly_sanitized(summaries["handle"], 0, {"html.escape"})
    assert not clean
    assert summaries["helper"].summary_unknown


def summaries_for(source):
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return graph, build_taint_summaries(graph, source)


def test_direct_local_reader_alias_cannot_forge_clean_path():
    source = SOURCE[:SOURCE.index('def helper(raw):')] + (
        'def helper(raw):\n    read_attribute = getattr\n'
        '    return read_attribute(witness, "value")\n'
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    graph, summaries = summaries_for(source)
    namespace = {'__name__': 'owned_direct_local_alias'}
    exec(compile(source, '<owned-direct-local-alias>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-direct-local-alias>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown_reason == 'calls read_attribute'
    assert graph.reflective_reader_aliases == frozenset()


def test_body_view_preserves_original_ast_nodes_and_fields():
    tree = ast.parse(SOURCE)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'helper')
    before = ast.dump(tree, include_attributes=True)
    identities = tuple(id(n) for n in ast.walk(tree))
    body = function.body
    assert _detect_summary_unknown(function) is not None
    assert function.body is body
    assert tuple(id(n) for n in ast.walk(tree)) == identities
    assert ast.dump(tree, include_attributes=True) == before


def test_unused_nested_local_alias_does_not_leak_to_outer_or_sibling():
    source = ('def helper(value):\n    def nested(obj, field):\n'
              '        read = getattr\n        return read(obj, field)\n    return value\n'
              'def sibling(value):\n    return value\n')
    graph, summaries = summaries_for(source)
    assert graph.reflective_reader_aliases == frozenset()
    assert not summaries['helper'].summary_unknown
    assert not summaries['sibling'].summary_unknown


def test_enclosing_reader_alias_keeps_existing_cell_reason():
    source = ('def helper(obj, field):\n    read = getattr\n    def nested():\n'
              '        return read(obj, field)\n    return nested()\n')
    _, summaries = summaries_for(source)
    assert summaries['helper'].summary_unknown_reason == 'returned local call depends on an unmodelled enclosing cell'


@pytest.mark.parametrize('body,reason', [
    ('read(obj, field, **mapping)\n    return 0', 'forwards **kwargs'),
    ('obj.__annotations__\n    return read(obj, field)', 'annotation metadata access may evaluate deferred expressions'),
])
def test_local_alias_fallback_preserves_existing_reason_priority(body, reason):
    source = 'def helper(obj, field, mapping):\n    read = getattr\n    ' + body + '\n'
    _, summaries = summaries_for(source)
    assert summaries['helper'].summary_unknown_reason == reason
