"""Repeated sequence copies preserve explicit shared member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_repeated_list_copy_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(list((werkzeug.utils,)))[0]', 'saved.secure_filename=replacement') is False


def test_repeated_tuple_copy_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=tuple(tuple([werkzeug.utils]))[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list(list((werkzeug.utils,)))[0]',
    'tuple(list((werkzeug.utils,)))[0]',
    'list([werkzeug.utils].copy())[0]',
    'list(list({werkzeug.utils:None}))[0]',
    'list((werkzeug.utils,) if condition else ())[0]',
    'list((holder:=tuple([werkzeug.utils])))[0]',
])
def test_supported_sequence_copy_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list(list((werkzeug.utils,)))\nsaved[0]=value',
    'import werkzeug\nsaved=list(tuple([werkzeug.utils]))\nsaved[0]=value',
    'import werkzeug\nsaved=list(factory((werkzeug.utils,)))[0]\nsaved.member=value',
    'import werkzeug\nsaved=list(werkzeug.copy())[0]\nsaved.member=value',
    'import werkzeug\nsaved=list([holder].copy())[0]\nsaved.member=value',
])
def test_fresh_sequence_writes_and_unknown_copy_origins_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
