"""Literal dictionary views retain distinct key and value references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_dictionary_value_view_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list({"utils":werkzeug.utils}.values())[0]', 'saved.secure_filename=replacement') is False


def test_dictionary_key_view_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=tuple({werkzeug.utils:None}.keys())[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list({"utils":werkzeug.utils}.values())[0]',
    'tuple({werkzeug.utils:None}.keys())[0]',
    'list(list({"utils":werkzeug.utils}.values()))[0]',
    'list((holder:={"utils":werkzeug.utils}).values())[0]',
])
def test_explicit_literal_view_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list({"utils":werkzeug.utils}.values())\nsaved[0]=value',
    'import werkzeug\nsaved=list({"key":werkzeug.utils}.keys())[0]\nsaved.member=value',
    'import werkzeug\nsaved=list({werkzeug.utils:None}.values())[0]\nsaved.member=value',
    'import werkzeug\nsaved=list(holder.values())[0]\nsaved.member=value',
    'import werkzeug\nsaved=list(werkzeug.values())[0]\nsaved.member=value',
])
def test_fresh_view_sequences_roles_and_unknown_receivers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
