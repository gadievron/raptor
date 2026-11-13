"""Copy chains retain supported fresh-set origins and member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_nested_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={werkzeug.utils}.copy().copy().pop()', 'saved.secure_filename=replacement') is False


def test_set_operation_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=({werkzeug.utils}|{werkzeug.utils}).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('depth', [1,8,64])
def test_supported_set_copy_chain_members_remove_trust(depth):
    source='import werkzeug\nsaved={werkzeug.utils}'+'.copy()'*depth+'.pop()\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('value', [
    '{werkzeug.utils}.difference({None}).copy().pop()',
    '{werkzeug.utils}.union().copy().copy().pop()',
    '(items:={werkzeug.utils}.copy().copy()).pop()',
])
def test_supported_set_operation_copy_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=holder'+'.copy()'*64+'.pop()\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug).copy().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={(werkzeug,)}.copy().copy().pop()\nsaved[0]=value',
    'import werkzeug\nsaved={werkzeug}.copy().copy()\nsaved.clear()',
    'import werkzeug\nsaved=(werkzeug,).copy().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"key":werkzeug}.copy().copy().pop()\nsaved.member=value',
])
def test_unknown_origins_fresh_members_and_other_container_kinds_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
