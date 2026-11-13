"""Nested sequence constructors retain selected mutable member origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_nested_sequence_constructor_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(tuple(([werkzeug.utils],)))[0].copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list(tuple(([werkzeug],)))[0].copy().pop()',
    'tuple(list(({werkzeug},))).__getitem__(0).copy().pop()',
    'tuple(list((part:=([werkzeug],))))[0].copy().pop()',
])
def test_nested_exact_member_reads_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('value', [
    'tuple(list(factory(werkzeug)))[0].copy().pop()',
    'tuple(list(([werkzeug],),extra))[0].copy().pop()',
    'tuple(list(([werkzeug],)))[index].copy().pop()',
    'tuple(list(([werkzeug],))).__getitem__(2).copy().pop()',
    'tuple(list({"k":[werkzeug]}))["k"].copy().pop()',
    'tuple(list(([werkzeug],))).pop().copy().pop()',
    'tuple(list(((werkzeug,),)))[0].copy().pop()',
])
def test_unknown_invalid_mapping_and_tuple_pop_remain_unrecognised(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (False, frozenset())
