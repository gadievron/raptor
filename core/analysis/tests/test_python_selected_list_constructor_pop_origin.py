"""Selected list constructions retain popped mutable member origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_selected_list_constructor_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[list(([werkzeug.utils],))][0].pop().copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[list(([werkzeug],))][0].pop().copy().pop()',
    '{"k":list(({werkzeug},))}["k"].pop(0).copy().pop()',
    '[None,list(tuple(([werkzeug],)))][-1].pop(-1).copy().pop()',
    '{"k":None,"k":list(([werkzeug],))}["k"].pop().copy().pop()',
])
def test_exact_selected_list_constructors_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('value', [
    '[list(([werkzeug],))][index].pop().copy().pop()',
    '{"k":list(([werkzeug],))}[key].pop().copy().pop()',
    '[list(([werkzeug],))][2].pop().copy().pop()',
    '{"k":list(([werkzeug],)),"k":None}["k"].pop().copy().pop()',
    '[list(factory(werkzeug))][0].pop().copy().pop()',
    '[list(([werkzeug],),extra)][0].pop().copy().pop()',
    '[tuple(([werkzeug],))][0].pop().copy().pop()',
    '[list(((werkzeug,),))][0].pop().copy().pop()',
    '[list(([werkzeug],))][0].pop().copy()',
])
def test_unknown_inputs_tuple_pop_and_fresh_results_keep_behavior(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (False, frozenset())
