"""Direct dictionary special-method mutations invalidate callable identity."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def source(receiver, method):
    return ('import werkzeug\nimport werkzeug as w\ndef handle(raw,replacement):\n'
            f'    {receiver}.__dict__.{method}({{"secure_filename":replacement}})\n'
            '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')


def suppression(text):
    cfg = build_python_cfg(text, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    return evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress


def test_imported_namespace_inplace_union_cannot_preserve_callable_identity():
    assert suppression(source('w.utils', '__ior__')) is False


@pytest.mark.parametrize('method', ['__ior__', '__init__'])
@pytest.mark.parametrize('receiver,expected', [
    ('w.utils', (True, frozenset())),
    ('globals()["werkzeug"].utils', (False, frozenset({'werkzeug'}))),
])
def test_dictionary_special_mutations_invalidate_imports_and_lookup_roots(method, receiver, expected):
    text = source(receiver, method)
    assert suppression(text) is False
    assert module_dynamic_namespace(ast.parse(text)) == expected


@pytest.mark.parametrize('text', [
    'import werkzeug as w\nsaved=w.utils.__dict__.__or__(other)',
    'import werkzeug as w\nother[w].__dict__.__ior__(replacement)',
    'import werkzeug as w\ndef handle():\n    value: w.utils.__dict__.__ior__(replacement)',
])
def test_nonmutating_union_unrelated_receiver_and_annotation_keep_existing_behavior(text):
    assert module_dynamic_namespace(ast.parse(text)) == (False, frozenset())
