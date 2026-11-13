"""Literal list pop returns an existing member object."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_list_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[werkzeug.utils].pop()', 'saved.secure_filename=replacement') is False


def test_indexed_list_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[werkzeug.utils].pop(0)', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[werkzeug.utils].pop()',
    '[werkzeug.utils].pop(0)',
    '[None,werkzeug.utils].pop(-1)',
])
def test_literal_list_pop_shared_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_list_pop_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=[werkzeug.utils.__dict__].pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=holder.pop()\nsaved.member=value',
    'import werkzeug\nsaved=[holder].pop(werkzeug)\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].pop()\nsaved[0]=value',
    'import werkzeug\nsaved=(werkzeug,).pop()\nsaved.member=value',
    'import werkzeug\nsaved=[werkzeug].pop(index=0)\nsaved.member=value',
])
def test_unknown_pop_index_inputs_fresh_members_and_invalid_shapes_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
