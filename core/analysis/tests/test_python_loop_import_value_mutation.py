"""Literal loop iterables can expose shared imported objects."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_loop_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('for saved in (werkzeug.utils,): saved.secure_filename=replacement', 'pass') is False


@pytest.mark.parametrize('statement', [
    'for saved in (werkzeug.utils,): saved.member=value',
    'for saved in [None,werkzeug.utils]: saved.member=value',
    'for saved,other in [(werkzeug.utils,None)]: saved.member=value',
    'for saved in (globals()["werkzeug"].utils,): saved.member=value',
])
def test_literal_loop_import_mutations_remove_trust(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+statement)) == (True, frozenset())


@pytest.mark.parametrize('statement', [
    'for saved in (werkzeug.utils,): pass',
    'for saved in factory(werkzeug): saved.member=value',
    'for saved in holder[werkzeug]: saved.member=value',
    'for other,saved in [(werkzeug.utils,None)]: saved.member=value',
])
def test_unused_loop_imports_and_unresolved_iterables_keep_behavior(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+statement)) == (False, frozenset())
