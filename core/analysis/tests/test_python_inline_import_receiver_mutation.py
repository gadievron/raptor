"""Inline imported value expressions can be mutation receivers."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_inline_reflective_receiver_cannot_preserve_replaced_callable_identity():
    assert suppression('getattr(werkzeug,"utils").secure_filename=replacement', 'pass') is False


def test_inline_copied_member_cannot_preserve_replaced_callable_identity():
    assert suppression('werkzeug.__dict__.copy()["utils"].secure_filename=replacement', 'pass') is False


@pytest.mark.parametrize('statement', [
    '(werkzeug.utils if condition else None).member=value',
    'setattr(getattr(werkzeug,"utils"),"member",value)',
    'saved=getattr(werkzeug,"utils").__setattr__',
    'getattr(werkzeug,"utils").__dict__.update(value)',
    'saved=getattr(werkzeug,"utils").__dict__.update',
])
def test_inline_known_import_mutations_remove_trust(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+statement)) == (True, frozenset())


@pytest.mark.parametrize('statement', [
    'getattr(holder,"member").field=value',
    'factory(werkzeug).field=value',
    'werkzeug.__dict__.copy()["member"]=value',
    'getattr(werkzeug,"__dict__").copy()["member"]=value',
])
def test_unresolved_receivers_and_fresh_mapping_writes_preserve_behavior(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+statement)) == (False, frozenset())


def test_direct_global_lookup_preserves_precise_named_root_policy():
    source='import werkzeug\nglobals()["werkzeug"].field=value'
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset({'werkzeug'}))
