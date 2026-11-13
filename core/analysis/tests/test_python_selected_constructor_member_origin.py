"""Literal selections retain constructed sequence member origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_selected_list_constructor_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[list(([werkzeug.utils],))][0][0].copy().pop()', 'saved.secure_filename=replacement') is False


def test_selected_tuple_constructor_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":tuple(({werkzeug.utils},))}["k"].__getitem__(0).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[list(([werkzeug],))][0][0].copy().pop()',
    '{"k":tuple(({werkzeug},))}["k"].__getitem__(0).copy().pop()',
    '[None,tuple(([werkzeug],))][-1][0].copy().pop()',
    '{"k":None,"k":list(([werkzeug],))}["k"][0].copy().pop()',
])
def test_exact_selected_constructors_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('value', [
    '[list(([werkzeug],))][index][0].copy().pop()',
    '{"k":tuple(([werkzeug],))}[key][0].copy().pop()',
    '[list(([werkzeug],))][2][0].copy().pop()',
    '{"k":tuple(([werkzeug],)),"k":None}["k"][0].copy().pop()',
    '[list(factory(werkzeug))][0][0].copy().pop()',
    '[list(([werkzeug],),extra)][0][0].copy().pop()',
    '[tuple(((werkzeug,),))][0][0].copy().pop()',
    '[list(([werkzeug],))][0][0].copy()',
])
def test_unknown_indices_sources_invalid_shapes_and_fresh_results_keep_behavior(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (False, frozenset())
