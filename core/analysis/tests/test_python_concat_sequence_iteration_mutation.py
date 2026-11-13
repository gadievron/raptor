"""Explicit iteration of literal concatenations retains shared members."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_concat_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter([werkzeug.utils]+[]))', 'saved.secure_filename=replacement') is False


def test_concat_loop_cannot_preserve_replaced_callable_identity():
    assert suppression('for saved in []+[werkzeug.utils]: saved.secure_filename=replacement', 'pass') is False


@pytest.mark.parametrize('value', [
    'next(iter([werkzeug.utils]+[]))',
    'list([]+[werkzeug.utils])[0]',
    'next(iter(()+(werkzeug.utils,)))',
    'tuple((werkzeug.utils,)+())[0]',
])
def test_same_kind_literal_concat_iteration_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_concat_sequence_iteration_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=next(iter([werkzeug.utils.__dict__]+[]))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter([werkzeug]+holder))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(holder+[werkzeug]))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter([werkzeug]+()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter([[werkzeug]]+[]))\nsaved[0]=value',
])
def test_unknown_mismatched_operands_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
