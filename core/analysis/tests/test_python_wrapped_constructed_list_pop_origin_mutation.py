"""Result wrappers retain exact popped collection origins from list construction."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_constructed_list_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(([werkzeug.utils],)).copy().pop().copy().pop()', 'saved.secure_filename=replacement') is False


def test_named_constructed_list_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(made:=list(({werkzeug.utils},))).pop(0).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list(([werkzeug.utils],)).copy().pop().copy().pop()',
    '(made:=list(({werkzeug.utils},))).pop(0).copy().pop()',
    '(made:=list(([werkzeug.utils],))).copy().copy().pop().copy().pop()',
    '(outer:=(inner:=list(([werkzeug.utils],)).copy())).pop().copy().pop()',
])
def test_wrapped_constructed_list_pop_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=(made:=list(factory(werkzeug))).copy().pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],)).copy(extra).pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(made:=list(([werkzeug],))).pop(index).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(made:=tuple(([werkzeug],))).pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],)).copy().pop().copy()\nsaved[0]=value',
])
def test_unknown_sources_invalid_shapes_indices_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
