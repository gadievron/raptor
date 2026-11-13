"""Synchronous comprehension targets retain supported iterable members."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_iterator_comprehension_cannot_preserve_replaced_callable_identity():
    assert suppression('[saved.__setattr__("secure_filename",replacement) for saved in iter((werkzeug.utils,))]', 'pass') is False


def test_copy_comprehension_cannot_preserve_replaced_callable_identity():
    assert suppression('[setattr(saved,"secure_filename",replacement) for saved in list((werkzeug.utils,))]', 'pass') is False


@pytest.mark.parametrize('expression', [
    '[saved.__setattr__("member",value) for saved in iter((werkzeug.utils,))]',
    '{saved.__setattr__("member",value) for saved in reversed([werkzeug.utils])}',
    '{key:saved.__setattr__("member",value) for saved in tuple((werkzeug.utils,))}',
])
def test_supported_comprehension_member_references_remove_trust(expression):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+expression)) == (True, frozenset())


def test_wrapped_comprehension_namespace_dictionary_members_keep_kind():
    source='import werkzeug\n[saved.update({}) for saved in iter((werkzeug.utils.__dict__,))]'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\n[saved.__setattr__("member",value) for saved in factory(werkzeug)]',
    'import werkzeug\n[saved.__setattr__("member",value) for saved in holder]',
    'import werkzeug\n[saved.__setattr__("member",value) for saved in {"key":werkzeug}]',
    'import werkzeug\n[saved.__setitem__(0,value) for saved in iter(([werkzeug.utils],))]',
    'import werkzeug\nasync def handle():\n    [saved.__setattr__("member",value) async for saved in iter((werkzeug.utils,))]',
])
def test_unknown_iterables_fresh_members_and_async_wrappers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
