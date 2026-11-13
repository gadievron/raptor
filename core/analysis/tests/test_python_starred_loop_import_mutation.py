"""Literal loop expansions retain references to supported source members."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_starred_loop_cannot_preserve_replaced_callable_identity():
    assert suppression('for saved in (*[werkzeug.utils],): saved.secure_filename=replacement', 'pass') is False


def test_starred_comprehension_cannot_preserve_replaced_callable_identity():
    assert suppression('[saved.__setattr__("secure_filename",replacement) for saved in (*[werkzeug.utils],)]', 'pass') is False


@pytest.mark.parametrize('statement', [
    'for saved in (*[werkzeug.utils],): saved.member=value',
    'for saved in [*iter((werkzeug.utils,))]: saved.member=value',
    'for saved,other in [*[(werkzeug.utils,None)]]: saved.member=value',
    'for saved in (*{werkzeug.utils:None},): saved.member=value',
])
def test_starred_supported_source_members_remove_trust(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+statement)) == (True, frozenset())


def test_starred_loop_keeps_namespace_dictionary_kind():
    source='import werkzeug\nfor saved in (*[werkzeug.utils.__dict__],): saved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('statement', [
    'for saved in (*factory(werkzeug),): saved.member=value',
    'for saved in (*holder,): saved.member=value',
    'for saved in (*{"key":werkzeug},): saved.member=value',
    'for saved in (*[[werkzeug.utils]],): saved[0]=value',
    'for other,saved in [*[(werkzeug.utils,None)]]: saved.member=value',
])
def test_unknown_expansions_keys_and_fresh_members_keep_behavior(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+statement)) == (False, frozenset())
