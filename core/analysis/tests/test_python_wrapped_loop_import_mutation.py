"""Synchronous loop targets retain supported iterator member identities."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_iterator_loop_cannot_preserve_replaced_callable_identity():
    assert suppression('for saved in iter((werkzeug.utils,)):\n        saved.secure_filename=replacement', 'pass') is False


def test_copy_loop_cannot_preserve_replaced_callable_identity():
    assert suppression('for saved in list((werkzeug.utils,)):\n        saved.secure_filename=replacement', 'pass') is False


@pytest.mark.parametrize('iterable', [
    'iter((werkzeug.utils,))',
    'list((werkzeug.utils,))',
    'reversed([werkzeug.utils])',
    '{werkzeug.utils:None}',
    '[[werkzeug.utils]][0]',
])
def test_supported_loop_member_references_remove_trust(iterable):
    source='import werkzeug\nfor saved in '+iterable+':\n    saved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


def test_wrapped_loop_namespace_dictionary_members_keep_kind():
    source='import werkzeug\nfor saved in iter((werkzeug.utils.__dict__,)):\n    saved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nfor saved in factory(werkzeug):\n    saved.member=value',
    'import werkzeug\nfor saved in holder:\n    saved.member=value',
    'import werkzeug\nfor saved in {"key":werkzeug}:\n    saved.member=value',
    'import werkzeug\nfor saved in iter(([werkzeug.utils],)):\n    saved[0]=value',
])
def test_unknown_iterables_dictionary_values_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
