"""Fixed owned nested getter frame-effect probe; no external source execution."""
import ast
import html

import pytest
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _detect_summary_unknown, build_taint_summaries
SOURCE = 'import sys\nimport html\nobserved = []\nclass Witness:\n    @property\n    def value(self):\n        current = sys._getframe()\n        try:\n            for _ in range(8):\n                if current is None:\n                    break\n                if current.f_code is helper.__code__:\n                    observed.append("owned-helper")\n                    return current.f_locals["raw"]\n                current = current.f_back\n            raise AssertionError("owned helper frame not present")\n        finally:\n            del current\nwitness = Witness()\ndef helper(raw):\n    def nested(read_attribute=getattr):\n        return read_attribute(witness, "value")\n    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)\n'
class Marker(str):
    pass

def test_default_getter_alias_cannot_forge_clean_path():
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


def assert_owned_flow_refused(source):
    _, summaries = summaries_for(source)
    namespace = {'__name__': 'owned_reader_default_variant'}
    exec(compile(source, '<owned-reader-default>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-reader-default>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('parameters,call', [
    ('read_attribute=getattr, /', 'nested()'),
    ('*, read_attribute=getattr', 'nested()'),
    ('*, required, read_attribute=getattr', 'nested(required=0)'),
    ('prefix, read_attribute=getattr', 'nested(0)'),
    ('prefix, /, *, read_attribute=getattr', 'nested(0)'),
])
def test_default_alignment_preserves_the_owned_reader_origin(parameters, call):
    source = SOURCE.replace('def nested(read_attribute=getattr):', 'def nested(' + parameters + '):')
    source = source.replace('return nested()', 'return ' + call)
    assert_owned_flow_refused(source)


def test_direct_default_reader_cannot_forge_clean_path():
    source = SOURCE[:SOURCE.index('def helper(raw):')] + (
        'def helper(raw, read_attribute=getattr):\n'
        '    return read_attribute(witness, "value")\n'
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    assert_owned_flow_refused(source)


def test_body_alias_does_not_retroactively_resolve_a_defining_frame_default():
    source = ('fallback = lambda obj, field: 0\n'
              'def helper(obj, field, reader=fallback):\n'
              '    fallback = getattr\n    return reader(obj, field)\n')
    _, summaries = summaries_for(source)
    assert not summaries['helper'].summary_unknown


@pytest.mark.parametrize('source', [
    'def helper(value, reader=getattr):\n    return value\n',
    'def helper(value):\n    def nested(reader=getattr):\n        return reader(witness, "value")\n    return value\n',
])
def test_unused_reader_defaults_keep_existing_precision(source):
    _, summaries = summaries_for(source)
    assert not summaries['helper'].summary_unknown


def test_default_binding_scan_preserves_ast_fields_and_identities():
    tree = ast.parse(SOURCE)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'helper')
    before = ast.dump(tree, include_attributes=True)
    identities = tuple(id(n) for n in ast.walk(tree))
    assert _detect_summary_unknown(function) is not None
    assert ast.dump(tree, include_attributes=True) == before
    assert tuple(id(n) for n in ast.walk(tree)) == identities


def test_default_reader_keeps_kwargs_reason_priority():
    source = ('def helper(obj, field, mapping, reader=getattr):\n'
              '    return reader(obj, field, **mapping)\n')
    _, summaries = summaries_for(source)
    assert summaries['helper'].summary_unknown_reason == 'forwards **kwargs'
