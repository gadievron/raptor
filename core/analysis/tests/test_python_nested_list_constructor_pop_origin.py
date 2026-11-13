"""List pop retains member origins through nested sequence construction."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_nested_list_constructor_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(tuple(([werkzeug.utils],))).pop().copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list(tuple(([werkzeug],))).pop().copy().pop()',
    'list(list(({werkzeug},))).pop(0).copy().pop()',
    'list(tuple([None,[werkzeug]])).pop(-1).copy().pop()',
    '(made:=list(tuple(([werkzeug],)))).copy().pop().copy().pop()',
])
def test_known_nested_sequence_sources_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('value', [
    'list(tuple(factory(werkzeug))).pop().copy().pop()',
    'list(tuple(([werkzeug],),extra)).pop().copy().pop()',
    'list(tuple(([werkzeug],))).pop(index).copy().pop()',
    'list(tuple(([werkzeug],))).pop(2).copy().pop()',
    'list(tuple({"k":[werkzeug]})).pop().copy().pop()',
    'tuple(list(([werkzeug],))).pop().copy().pop()',
    'list(tuple(((werkzeug,),))).pop().copy().pop()',
])
def test_unknown_invalid_mapping_and_tuple_pop_remain_unrecognised(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (False, frozenset())
