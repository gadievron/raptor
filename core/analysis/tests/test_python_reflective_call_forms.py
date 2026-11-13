"""Reflective write spellings preserve shared namespace mutation semantics."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def suppression(statement, imports=''):
    source = ('import werkzeug.utils\n' + imports + '\ndef handle(raw,replacement):\n'
              '    ' + statement + '\n    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    return evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                            source_symbols={'raw'}, sink_arg='tmp').suppress


def test_imported_builtin_setter_alias_cannot_preserve_replaced_callable_identity():
    assert suppression('edit(werkzeug.utils,"secure_filename",replacement)',
                       'from builtins import setattr as edit') is False


def test_bound_setter_cannot_preserve_replaced_callable_identity():
    assert suppression('werkzeug.utils.__setattr__("secure_filename",replacement)') is False


@pytest.mark.parametrize('source,expected', [
    ('import werkzeug\nfrom builtins import delattr as edit\nedit(werkzeug.utils,"secure_filename")', (True, frozenset())),
    ('def handle():\n    import werkzeug as w\n    from builtins import setattr as edit\n    edit(w.utils,"field",replacement)', (True, frozenset())),
    ('from builtins import setattr as edit\nedit(globals()["root"].child,"field",replacement)', (False, frozenset({'root'}))),
    ('globals()["root"].child.__delattr__("field")', (False, frozenset({'root'}))),
    ('import werkzeug\nwerkzeug.__dict__["utils"].__setattr__("field",replacement)', (True, frozenset())),
])
def test_reflective_receiver_forms_invalidate_the_matching_namespace(source, expected):
    assert module_dynamic_namespace(ast.parse(source)) == expected


@pytest.mark.parametrize('source', [
    'from builtins import setattr as edit\nedit(holder,"field",replacement)',
    'holder.__setattr__("field",replacement)',
    'from builtins import setattr as edit\nedit(holder[globals()["root"]],"field",replacement)',
    'holder.__setattr__(globals()["root"],replacement)',
    'from .builtins import setattr as edit\nedit(holder,"field",replacement)',
    'import werkzeug\nfrom .builtins import setattr as edit\nedit(werkzeug.utils,"field",replacement)',
    'from builtins import setattr as edit',
    'import werkzeug\ndef handle():\n    value: werkzeug.utils.__setattr__("field",replacement)',
])
def test_unrelated_receivers_unused_aliases_and_inert_annotations_keep_existing_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
