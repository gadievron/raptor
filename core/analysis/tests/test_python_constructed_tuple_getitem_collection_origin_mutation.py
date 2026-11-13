"""Tuple construction retains nested collection origins through member reads."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_constructed_tuple_subscript_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=tuple(([werkzeug.utils],))[0].copy().pop()', 'saved.secure_filename=replacement') is False


def test_constructed_tuple_getitem_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=tuple(({werkzeug.utils},)).__getitem__(0).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'tuple(([werkzeug.utils],))[0].copy().pop()',
    'tuple(({werkzeug.utils},)).__getitem__(0).copy().pop()',
    'tuple([None,[werkzeug.utils]])[-1].copy().pop()',
    '(made:=tuple(([werkzeug.utils],)))[0].copy().pop()',
])
def test_exact_tuple_construction_reads_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=tuple(factory(werkzeug))[0].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=tuple(([werkzeug],),extra)[0].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=tuple(([werkzeug],))[index].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=tuple(([werkzeug],)).__getitem__(1).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=tuple(((werkzeug,),))[0].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=tuple(([werkzeug],)).pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=tuple(([werkzeug],))[0].copy()\nsaved[0]=value',
])
def test_unknown_inputs_invalid_pop_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
