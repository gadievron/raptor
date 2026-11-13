"""List concatenation retains known copied operand origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_left_list_concat_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([werkzeug.utils].copy()+[]).pop()', 'saved.secure_filename=replacement') is False


def test_copied_right_list_concat_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([]+[werkzeug.utils].copy()).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '([werkzeug.utils].copy()+[]).pop()',
    '([]+[werkzeug.utils].copy()).copy().pop()',
    '(list((werkzeug.utils,))+[]).pop()',
    '([werkzeug.utils][:]+[]).copy().pop()',
    '(([werkzeug.utils] if flag else [])+[]).pop()',
    '(([werkzeug.utils].copy()+[])+[]).pop()',
])
def test_known_list_concat_member_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_list_concat_preserves_member_namespace_dictionary_kind():
    source='import werkzeug\nsaved=([werkzeug.utils.__dict__].copy()+[]).pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=(factory(werkzeug)+[]).pop()\nsaved.member=value',
    'import werkzeug\nsaved=([werkzeug].copy()+()).pop()\nsaved.member=value',
    'import werkzeug\nsaved=((werkzeug,)+()).pop()\nsaved.member=value',
    'import werkzeug\nsaved=({werkzeug}.copy()+[]).pop()\nsaved.member=value',
    'import werkzeug\nsaved=[werkzeug].copy()+[]\nsaved[0]=value',
    'import werkzeug\nsaved=([[werkzeug]].copy()+[]).pop()\nsaved[0]=value',
])
def test_unknown_mixed_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
