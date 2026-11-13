"""Reflective mutation of namespace lookup values loses callable trust."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_reflective_global_lookup_write_cannot_preserve_callable_identity():
    source = ('import werkzeug\ndef handle(raw,replacement):\n'
              '    setattr(globals()["werkzeug"].utils,"secure_filename",replacement)\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is False
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset({"werkzeug"}))


@pytest.mark.parametrize("source,expected", [
    ('setattr(globals()["root"],"member",replacement)', (False, frozenset({"root"}))),
    ('delattr(vars()["root"].items[0],"member")', (False, frozenset({"root"}))),
    ('setattr(locals()["root"],"member",replacement)', (False, frozenset({"root"}))),
    ('setattr(globals()[key],"member",replacement)', (True, frozenset())),
    ('setattr(vars(obj)["root"],"member",replacement)', (True, frozenset())),
    ('setattr(other[globals()["root"]],"member",replacement)', (False, frozenset())),
    ('setattr(factory(globals()["root"]),"member",replacement)', (False, frozenset())),
    ('saved=globals()["root"].member', (False, frozenset())),
    ('def handle():\n    setattr(locals()["root"],"member",replacement)', (True, frozenset())),
    ('def handle():\n    value: setattr(globals()["root"],"member",replacement)', (False, frozenset())),
])
def test_namespace_receiver_position_and_existing_scope_limits(source, expected):
    assert module_dynamic_namespace(ast.parse(source)) == expected
