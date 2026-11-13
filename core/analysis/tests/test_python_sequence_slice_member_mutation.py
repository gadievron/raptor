"""Slices preserve sequence members without becoming those member objects."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_list_slice_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(list((werkzeug.utils,))[:])[0]', 'saved.secure_filename=replacement') is False


def test_copied_tuple_slice_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=tuple(tuple([werkzeug.utils])[:])[0]', 'saved.secure_filename=replacement') is False


def test_direct_constructor_slice_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list((werkzeug.utils,))[:][0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list(list((werkzeug.utils,))[:])[0]',
    'tuple(tuple([werkzeug.utils])[:])[0]',
    'list((werkzeug.utils,))[:][0]',
    'list((werkzeug.utils,)).copy()[:][0]',
    'list((holder:=list((werkzeug.utils,)))[:])[0]',
])
def test_known_sequence_slice_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list((werkzeug.utils,))[:]\nsaved[0]=value',
    'import werkzeug\nsaved=tuple([werkzeug.utils])[:]\nsaved.member=value',
    'import werkzeug\nsaved=list(holder[:])[0]\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug)[:][0]\nsaved.member=value',
])
def test_slice_container_writes_and_unknown_slice_origins_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
