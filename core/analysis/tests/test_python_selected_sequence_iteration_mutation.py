"""Explicit iteration of a selected literal sequence retains its members."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_selected_sequence_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter([[werkzeug.utils]][0]))', 'saved.secure_filename=replacement') is False


def test_selected_sequence_copy_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list([[werkzeug.utils]][0])[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter([[werkzeug.utils]][0]))',
    'list({"chosen":[werkzeug.utils]}["chosen"])[0]',
    'tuple((holder,[werkzeug.utils])[-1])[0]',
    'next(reversed([[werkzeug.utils]][0]))',
])
def test_selected_sequence_iteration_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_selected_sequence_dictionary_members_keep_kind():
    source='import werkzeug\nsaved=next(iter([[werkzeug.utils.__dict__]][0]))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list([[werkzeug.utils],[]][1])[0]\nsaved.member=value',
    'import werkzeug\nsaved=list([[werkzeug.utils]][index])[0]\nsaved.member=value',
    'import werkzeug\nsaved=list(factory(werkzeug)[0])[0]\nsaved.member=value',
    'import werkzeug\nsaved=next(iter([[[werkzeug.utils]]][0]))\nsaved[0]=value',
])
def test_unknown_selection_and_fresh_nested_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
