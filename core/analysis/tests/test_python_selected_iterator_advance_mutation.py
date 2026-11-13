"""Literal member selection preserves stored iterator identity."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_selected_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next([iter((werkzeug.utils,))][0])', 'saved.secure_filename=replacement') is False


def test_selected_bound_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"chosen":iter((werkzeug.utils,))}["chosen"].__next__()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next([iter((werkzeug.utils,))][0])',
    'next((holder,reversed([werkzeug.utils]))[-1])',
    'next({"chosen":iter((werkzeug.utils,))}["chosen"])',
    'next([[iter((werkzeug.utils,))]][0][0])',
])
def test_selected_supported_iterators_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_selected_iterator_preserves_namespace_dictionary_kind():
    source='import werkzeug\nsaved=next([iter((werkzeug.utils.__dict__,))][0])\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next([iter((werkzeug.utils,)),holder][1])\nsaved.member=value',
    'import werkzeug\nsaved=next([iter((werkzeug.utils,))][offset])\nsaved.member=value',
    'import werkzeug\nsaved=next(factory(werkzeug)[0])\nsaved.member=value',
    'import werkzeug\nsaved=next([iter(([werkzeug.utils],))][0])\nsaved[0]=value',
])
def test_unselected_unknown_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
