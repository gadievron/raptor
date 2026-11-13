"""Positive list repetition retains known copied origins once."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_list_repeat_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([werkzeug.utils].copy()*2).pop()', 'saved.secure_filename=replacement') is False


def test_reversed_copied_list_repeat_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(2*[werkzeug.utils].copy()).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '([werkzeug.utils].copy()*2).pop()',
    '(2*[werkzeug.utils].copy()).copy().pop()',
    '(list((werkzeug.utils,))*2).pop()',
    '([werkzeug.utils][:]*2).pop()',
    '(([werkzeug.utils] if flag else [])*2).pop()',
    '(([werkzeug.utils].copy()*2)*3).pop()',
    '([werkzeug.utils].copy()*1000000000000000000000000000000000000).pop()',
])
def test_known_list_repeat_member_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_list_repeat_preserves_namespace_dictionary_member_kind():
    source='import werkzeug\nsaved=([werkzeug.utils.__dict__].copy()*2).pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('value', [
    'factory(werkzeug)*2', '[werkzeug].copy()*0', '[werkzeug].copy()*-1',
    '[werkzeug].copy()*True', '[werkzeug].copy()*2.0', '[werkzeug].copy()*count',
    '(werkzeug,)*2', '{werkzeug}.copy()*2',
])
def test_unknown_source_or_count_nonpositive_and_other_kinds_keep_behavior(value):
    source='import werkzeug\nsaved=('+value+').pop()\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_repeated_list_result_remains_fresh():
    source='import werkzeug\nsaved=[werkzeug].copy()*2\nsaved[0]=value'
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
