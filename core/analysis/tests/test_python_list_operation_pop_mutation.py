"""Supported literal list operation results retain popped references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[werkzeug.utils].copy().pop()', 'saved.secure_filename=replacement') is False


def test_list_concat_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([werkzeug.utils]+[]).pop()', 'saved.secure_filename=replacement') is False


def test_list_repeat_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([werkzeug.utils]*2).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[werkzeug.utils].copy().pop()',
    '([]+[werkzeug.utils]).pop()',
    '(2*[werkzeug.utils]).pop()',
    '(items:=[werkzeug.utils].copy()).pop()',
])
def test_supported_literal_list_operation_pop_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_list_operation_pop_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=([werkzeug.utils.__dict__]+[]).pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=holder.copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=([werkzeug]+holder).pop()\nsaved.member=value',
    'import werkzeug\nsaved=([werkzeug]*count).pop()\nsaved.member=value',
    'import werkzeug\nsaved=([werkzeug]*0).pop()\nsaved.member=value',
    'import werkzeug\nsaved=((werkzeug,)+()).pop()\nsaved.member=value',
    'import werkzeug\nsaved=([[werkzeug]]+[]).pop()\nsaved[0]=value',
    'import werkzeug\nsaved=[werkzeug].copy()\nsaved[0]=value',
])
def test_unknown_origins_counts_tuple_results_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
