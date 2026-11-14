"""Fixed owned nested getter frame-effect probe; no external source execution."""
import ast
import html

import pytest
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries
SOURCE = 'import sys\nimport html\nread_attribute = getattr\nobserved = []\nclass Witness:\n    @property\n    def value(self):\n        current = sys._getframe()\n        try:\n            for _ in range(8):\n                if current is None:\n                    break\n                if current.f_code is helper.__code__:\n                    observed.append("owned-helper")\n                    return current.f_locals["raw"]\n                current = current.f_back\n            raise AssertionError("owned helper frame not present")\n        finally:\n            del current\nwitness = Witness()\ndef helper(raw):\n    def nested():\n        return read_attribute(witness, "value")\n    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)\n'
class Marker(str):
    pass

def test_stored_getter_alias_cannot_forge_clean_path():
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


def test_direct_stored_getter_cannot_forge_clean_path():
    source = SOURCE[:SOURCE.index('def helper(raw):')] + (
        'def helper(raw):\n    return read_attribute(witness, "value")\n'
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    _, summaries = summaries_for(source)
    namespace = {'__name__': 'owned_direct_reader_alias_fixture'}
    exec(compile(source, '<owned-direct-reader-alias>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-direct-reader-alias>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown_reason == 'calls read_attribute'


def test_stored_hasattr_effects_cannot_forge_clean_path():
    source = SOURCE.replace('read_attribute = getattr', 'read_attribute = hasattr')
    source = source.replace('observed.append("owned-helper")', 'observed.append(current.f_locals["raw"])')
    source = source.replace('return read_attribute(witness, "value")',
                            'read_attribute(witness, "value")\n        return observed[-1]')
    _, summaries = summaries_for(source)
    namespace = {'__name__': 'owned_check_alias_fixture'}
    exec(compile(source, '<owned-check-alias>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-check-alias>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('bindings,expected', [
    ('read = getattr\n', {'read'}),
    ('check = hasattr\nsecond = check\n', {'check', 'second'}),
    ('first = second\nsecond = first\nfirst = getattr\n', {'first', 'second'}),
    ('first = second\nsecond = first\n', set()),
    ('read = "getattr"\n', set()),
    ('import builtins as b\nread = b.getattr\n', {'b.getattr', 'b.hasattr', 'read'}),
])
def test_reader_alias_candidates_stay_separate_from_annotation_and_import_identities(bindings, expected):
    from core.analysis.python_module_callgraph import module_import_map
    graph, _ = summaries_for(bindings + '\ndef unrelated(value):\n    return value\n')
    assert graph.reflective_reader_aliases == frozenset(expected)
    assert graph.annotation_evaluator_aliases == frozenset()
    assert graph.import_map == module_import_map(ast.parse(bindings))


def test_unused_nested_reader_alias_keeps_precision():
    _, summaries = summaries_for('read = getattr\ndef helper(value):\n'
                                 '    def nested(obj, field):\n        return read(obj, field)\n'
                                 '    return value\n')
    assert not summaries['helper'].summary_unknown


@pytest.mark.parametrize('body,reason', [
    ('read(obj, field, **mapping)\n    return 0', 'forwards **kwargs'),
    ('read(obj, field)\n    global external\n    return 0', 'declares global external'),
    ('obj.__annotations__\n    return read(obj, field)', 'annotation metadata access may evaluate deferred expressions'),
    ('read(obj, field)\n    def nested():\n        return value\n    return nested',
     'returned function retains an unmodelled enclosing cell'),
])
def test_reader_alias_does_not_preempt_existing_reasons(body, reason):
    _, summaries = summaries_for('read = getattr\ndef helper(value, obj, field, mapping):\n    ' + body + '\n')
    assert summaries['helper'].summary_unknown_reason == reason
