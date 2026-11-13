"""Copy chains retain supported fresh-list origins and member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_nested_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[werkzeug.utils].copy().copy().pop()', 'saved.secure_filename=replacement') is False


def test_list_operation_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([werkzeug.utils]+[]).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('depth', [1,8,64])
def test_supported_copy_chain_members_remove_trust(depth):
    source='import werkzeug\nsaved=[werkzeug.utils]'+'.copy()'*depth+'.pop()\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


def test_list_copy_chain_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=[werkzeug.utils.__dict__].copy().copy().pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=holder'+'.copy()'*64+'.pop()\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug).copy().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].copy().copy().pop()\nsaved[0]=value',
    'import werkzeug\nsaved=[werkzeug].copy().copy()\nsaved[0]=value',
    'import werkzeug\nsaved=([werkzeug]*0).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(werkzeug,).copy().copy().pop()\nsaved.member=value',
])
def test_unknown_origins_fresh_members_nonpositive_counts_and_tuple_copy_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
