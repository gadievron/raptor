"""Class namespace lookup keys do not identify module import roots."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_class_local_value_write_cannot_preserve_shared_callable_identity():
    source = ('import werkzeug.utils\nclass Configure:\n'
              '    import werkzeug as local_module\n'
              '    locals()["local_module"].utils.secure_filename=replacement\n'
              'def handle(raw):\n    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                            source_symbols={'raw'}, sink_arg='tmp').suppress is False


@pytest.mark.parametrize('statement', [
    'locals()["alias"].member=replacement',
    'vars()["alias"].member=replacement',
    'setattr(locals()["alias"],"member",replacement)',
    'saved=vars()["alias"].__setattr__',
    'def method(value=locals()["alias"].__setattr__): pass',
])
def test_class_value_mutations_remove_whole_namespace_trust(statement):
    assert module_dynamic_namespace(ast.parse('class Configure:\n    '+statement)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'class Configure:\n    saved=locals()["alias"].member',
    'class Configure(locals()["alias"].member): pass',
    'class Configure:\n    def method(value=locals()["alias"].member): pass',
])
def test_class_reads_and_definition_expressions_preserve_existing_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_module_class_base_expression_keeps_module_key_policy():
    assert module_dynamic_namespace(ast.parse('class Configure(setattr(locals()["root"],"member",value)): pass')) == (False, frozenset({'root'}))
