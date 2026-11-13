"""Shallow dictionary copies retain key and value view references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_values_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({"chosen":werkzeug.utils}.copy().values()))', 'saved.secure_filename=replacement') is False


def test_copied_keys_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({werkzeug.utils:None}.copy().keys()))', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter({"chosen":werkzeug.utils}.copy().values()))',
    'list({werkzeug.utils:None}.copy().copy().keys())[0]',
    'next(iter(dict(chosen=werkzeug.utils).copy().values()))',
])
def test_supported_copy_chain_views_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_copied_values_keep_namespace_dictionary_kind():
    source='import werkzeug\nsaved=next(iter({"chosen":werkzeug.utils.__dict__}.copy().values()))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter({"key":werkzeug}.copy().keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({werkzeug:holder}.copy().values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(holder.copy().values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({"key":[werkzeug]}.copy().values()))\nsaved[0]=value',
    'import werkzeug\nsaved={"key":werkzeug}.copy()\nsaved["key"]=value',
    'import werkzeug\nsaved=next(iter({"key":werkzeug}.copy(0).values()))\nsaved.member=value',
])
def test_key_value_roles_unknown_origins_and_fresh_mappings_or_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
