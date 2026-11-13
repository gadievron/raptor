"""Reflective stores through imported item receivers invalidate identity."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_reflective_import_subscript_write_cannot_preserve_callable_identity():
    source = ('import werkzeug\nimport werkzeug as w\ndef handle(raw,replacement):\n'
              '    setattr(w.__dict__["utils"],"secure_filename",replacement)\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is False
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize("statement", [
    'setattr(w.__dict__["utils"],"secure_filename",replacement)',
    'delattr(w.__dict__["utils"],"secure_filename")',
    'setattr(w.items[0].child,"name",replacement)',
    'setattr(w[0],"name",replacement)',
    'setattr(w.items[key].child,"name",replacement)',
])
def test_reflective_mixed_import_receivers_are_uncertain(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug as w\n' + statement))[0] is True


def test_local_import_reflective_item_receiver_is_uncertain():
    source = ('def handle(replacement):\n    import werkzeug as w\n'
              '    setattr(w.__dict__["utils"],"secure_filename",replacement)')
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize("source", [
    'def handle(value):\n    setattr(value[0],"name",replacement)',
    'import werkzeug as w\nsetattr(other[w],"name",replacement)',
    'import werkzeug as w\nsetattr(factory(w),"name",replacement)',
    'import werkzeug as w\nsaved=w.__dict__["utils"]',
    'import werkzeug as w\ndef handle():\n'
    '    value: setattr(w.__dict__["utils"],"secure_filename",replacement)',
])
def test_unrelated_and_unsupported_receivers_keep_existing_namespace_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
