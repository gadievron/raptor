"""Escaped reflective write capabilities invalidate callable namespace trust."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def suppression(binding, call):
    text = ('import werkzeug.utils\ndef handle(raw,replacement):\n'
            '    ' + binding + '\n    ' + call + '\n'
            '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(text, 'handle')
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    return evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                            source_symbols={'raw'}, sink_arg='tmp').suppress


def test_escaped_builtin_setter_cannot_preserve_replaced_callable_identity():
    assert suppression('edit=setattr', 'edit(werkzeug.utils,"secure_filename",replacement)') is False


def test_escaped_bound_setter_cannot_preserve_replaced_callable_identity():
    assert suppression('edit=werkzeug.utils.__setattr__', 'edit("secure_filename",replacement)') is False


@pytest.mark.parametrize('source,expected', [
    ('saved=delattr', (True, frozenset())),
    ('from builtins import setattr as edit\nsaved=edit', (True, frozenset())),
    ('import werkzeug\nsaved=werkzeug.utils.__delattr__', (True, frozenset())),
    ('saved=globals()["root"].child.__setattr__', (False, frozenset({'root'}))),
    ('consume(globals()["root"].__delattr__)', (False, frozenset({'root'}))),
])
def test_setter_value_exposure_removes_matching_namespace_trust(source, expected):
    assert module_dynamic_namespace(ast.parse(source)) == expected


@pytest.mark.parametrize('source', [
    'setattr(holder,"field",replacement)',
    'holder.__setattr__("field",replacement)',
    'from builtins import setattr as edit\nedit(holder,"field",replacement)',
    'from builtins import setattr as edit',
    'saved=holder.__setattr__',
    'def handle():\n    value: setattr',
    'import werkzeug\ndef handle():\n    value: werkzeug.utils.__setattr__',
])
def test_unrelated_direct_calls_unused_imports_and_local_annotations_keep_existing_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
