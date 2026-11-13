"""Copied literal dictionary expansions retain iterated value references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_expanded_literal_values_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter(dict({**{"chosen":werkzeug.utils}}).values()))', 'saved.secure_filename=replacement') is False


def test_expanded_literal_values_copy_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(dict(**{**{"chosen":werkzeug.utils}}).values())[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter(dict({**{"chosen":werkzeug.utils}}).values()))',
    'list(dict(**{**{"chosen":werkzeug.utils}}).values())[0]',
    'next(iter(dict({**{**{"chosen":werkzeug.utils}}}).values()))',
])
def test_literal_expansion_values_iteration_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_expanded_literal_values_keep_namespace_dictionary_kind():
    source='import werkzeug\nsaved=next(iter(dict({**{"chosen":werkzeug.utils.__dict__}}).values()))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter(dict({**{werkzeug:holder}}).values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict({**factory(werkzeug)}).values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict({**{"key":[werkzeug]}}).values()))\nsaved[0]=value',
    'import werkzeug\nsaved=next(iter(dict({**{"key":werkzeug}}).keys()))\nsaved.member=value',
])
def test_keys_unknown_expansions_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
