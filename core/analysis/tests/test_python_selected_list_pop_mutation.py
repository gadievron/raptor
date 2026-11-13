"""Selected literal lists retain member identity through zero-argument pop."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_named_list_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(items:=[werkzeug.utils]).pop()', 'saved.secure_filename=replacement') is False


def test_selected_list_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[[werkzeug.utils]][0].pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '(items:=[werkzeug.utils]).pop()',
    '[[werkzeug.utils]][0].pop()',
    '{"chosen":[werkzeug.utils]}["chosen"].pop()',
])
def test_selected_literal_list_pop_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_selected_list_pop_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=[[werkzeug.utils.__dict__]][0].pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=holder.pop()\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug)[0].pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]][index].pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[[werkzeug]]][0].pop()\nsaved[0]=value',
])
def test_unknown_selected_lists_and_fresh_returned_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
