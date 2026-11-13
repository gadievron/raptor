"""Explicit sequence construction from a mapping returns key references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_list_key_reference_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list({werkzeug.utils:None})[0]', 'saved.secure_filename=replacement') is False


def test_tuple_key_reference_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=tuple({werkzeug.utils:None})[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list({werkzeug.utils:None})[0]',
    'tuple({werkzeug.utils:None})[0]',
    'list((holder:={werkzeug.utils:None}))[0]',
    'list({"inner":{werkzeug.utils:None}}["inner"])[0]',
])
def test_literal_dictionary_iteration_exposes_key_objects(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list({werkzeug.utils:None})\nsaved[0]=value',
    'import werkzeug\nsaved={werkzeug.utils:None}[key]\nsaved.member=value',
    'import werkzeug\nsaved=dict({werkzeug.utils:None})[key]\nsaved.member=value',
    'import werkzeug\nsaved=list(factory(werkzeug))[0]\nsaved.member=value',
    'import werkzeug\nsaved=list({holder:None})[0]\nsaved.member=value',
])
def test_key_iteration_does_not_change_mapping_value_or_fresh_container_rules(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_constructor_alias_collision_preserves_sequence_key_projection():
    source='import werkzeug\nfrom builtins import list as dict\nsaved=dict({werkzeug.utils:None})[0]\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())
