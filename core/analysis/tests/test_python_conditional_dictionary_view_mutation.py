"""Possible mapping result origins retain dictionary view references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_conditional_values_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter(({"chosen":werkzeug.utils} if raw else {}).values()))', 'saved.secure_filename=replacement') is False


def test_conditional_keys_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter(({werkzeug.utils:None} if raw else {}).keys()))', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter(({"chosen":werkzeug.utils} if raw else holder).values()))',
    'next(iter((holder or {werkzeug.utils:None}).keys()))',
    'next(iter(({"chosen":werkzeug.utils} if raw else {}).copy().values()))',
    'next(iter((items:=(dict(chosen=werkzeug.utils) if raw else {})).values()))',
])
def test_possible_supported_mapping_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_conditional_values_keep_namespace_dictionary_kind():
    source='import werkzeug\nsaved=next(iter(({"chosen":werkzeug.utils.__dict__} if raw else {}).values()))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter((holder if werkzeug else {}).values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(({"key":werkzeug} if raw else {}).keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(({werkzeug:holder} if raw else {}).values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(({"key":[werkzeug]} if raw else {}).values()))\nsaved[0]=value',
    'import werkzeug\nsaved=next(iter((factory(werkzeug) if raw else {}).values()))\nsaved.member=value',
])
def test_conditions_key_value_roles_unknown_origins_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
