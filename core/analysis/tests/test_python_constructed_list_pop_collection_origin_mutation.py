"""List constructors over literal sequences retain popped collection origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_constructed_list_pop_list_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(([werkzeug.utils],)).pop().copy().pop()', 'saved.secure_filename=replacement') is False


def test_constructed_list_pop_set_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(({werkzeug.utils},)).pop(0).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list(([werkzeug.utils],)).pop().copy().pop()',
    'list(({werkzeug.utils},)).pop(0).copy().pop()',
    'list([None,[werkzeug.utils]]).pop(-1).copy().pop()',
    'list([[werkzeug.utils]].copy()).pop().copy().pop()',
])
def test_constructed_list_exact_pop_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_list_constructor_alias_keeps_popped_collection_origin():
    source='import werkzeug\nfrom builtins import list as make_list\nsaved=make_list(([werkzeug.utils],)).pop().copy().pop()\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list(factory(werkzeug)).pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],),extra).pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],)).pop(index).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=tuple(([werkzeug],)).pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],)).pop(1).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],)).pop().copy()\nsaved[0]=value',
])
def test_unknown_sources_invalid_shapes_indices_other_kinds_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
