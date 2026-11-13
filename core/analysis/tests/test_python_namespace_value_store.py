"""A namespace lookup may be a receiver of a direct object mutation."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_direct_store_through_globals_lookup_rejects_replaced_callable():
    source = ('import werkzeug\ndef handle(raw,replacement):\n'
              '    globals()["werkzeug"].utils.secure_filename=replacement\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is False
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset({"werkzeug"}))


@pytest.mark.parametrize("statement", [
    'globals()["state"].field=value',
    'vars()["state"]["field"]=value',
    'del globals()["state"].nested.field',
    'globals()["state"].nested["field"]+=value',
])
def test_direct_receiver_store_chains_poison_the_lookup_root(statement):
    assert module_dynamic_namespace(ast.parse(statement)) == (False, frozenset({"state"}))


def test_computed_lookup_receiver_store_is_whole_namespace_uncertainty():
    assert module_dynamic_namespace(ast.parse('globals()[key].field=value'))[0] is True


@pytest.mark.parametrize("statement", [
    'saved=globals()["state"]',
    'saved=globals()["state"].field',
    'other[globals()["state"]]=value',
])
def test_plain_reads_and_store_keys_are_not_receiver_writes(statement):
    assert module_dynamic_namespace(ast.parse(statement)) == (False, frozenset())


@pytest.mark.parametrize("statement", [
    'vars(werkzeug)["utils"].secure_filename=replacement',
    'vars(werkzeug.utils)["secure_filename"]=replacement',
])
def test_object_namespace_write_does_not_mistake_member_key_for_global_root(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n' + statement))[0] is True
