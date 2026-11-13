"""Possible set result operands retain references through zero-argument pop."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_conditional_set_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=({werkzeug.utils} if raw else {werkzeug.utils}).pop()', 'saved.secure_filename=replacement') is False


def test_boolean_set_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=({werkzeug.utils} or {None}).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '({werkzeug.utils} if raw else holder).pop()',
    '(holder or {werkzeug.utils}).pop()',
    '(items:=({werkzeug.utils}.union() if raw else holder)).pop()',
    '({werkzeug.utils}.copy() if raw else holder).pop()',
])
def test_possible_supported_set_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=({holder} if werkzeug else other).pop()\nsaved.member=value',
    'import werkzeug\nsaved=(factory(werkzeug) if raw else holder).pop()\nsaved.member=value',
    'import werkzeug\nsaved=({(werkzeug,)} if raw else holder).pop()\nsaved[0]=value',
    'import werkzeug\nsaved=({werkzeug} if raw else holder)\nsaved.clear()',
    'import werkzeug\nsaved=({werkzeug} if raw else holder).pop(0)\nsaved.member=value',
])
def test_conditions_unknown_origins_fresh_members_and_invalid_set_pop_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
