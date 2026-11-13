"""Constructed lists retain selected collection origins through member reads."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_constructed_list_subscript_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(([werkzeug.utils],))[0].copy().pop()', 'saved.secure_filename=replacement') is False


def test_constructed_list_getitem_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(({werkzeug.utils},)).__getitem__(0).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list(([werkzeug.utils],))[0].copy().pop()',
    'list(({werkzeug.utils},)).__getitem__(0).copy().pop()',
    'list([None,[werkzeug.utils]])[-1].copy().pop()',
    'list(([werkzeug.utils],)).copy()[0].copy().pop()',
    '(made:=list(([werkzeug.utils],))).__getitem__(0).copy().pop()',
])
def test_constructed_list_exact_read_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list(factory(werkzeug))[0].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],),extra)[0].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],))[index].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],)).__getitem__(1).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(((werkzeug,),))[0].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(([werkzeug],))[0].copy()\nsaved[0]=value',
])
def test_unknown_shapes_indices_other_kinds_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
