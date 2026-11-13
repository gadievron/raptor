"""Literal dictionary expansion preserves original key object references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_expanded_dictionary_keys_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({**{werkzeug.utils:None}}.keys()))', 'saved.secure_filename=replacement') is False


def test_expanded_constructor_keys_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(dict({**{werkzeug.utils:None}}).keys())[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('statement', [
    'saved=next(iter({**{werkzeug.utils:None}}.keys())); saved.member=value',
    'for saved in {**{werkzeug.utils:None}}: saved.member=value',
    'saved=next(iter({**{**{werkzeug.utils:None}}})); saved.member=value',
    'saved=next(iter({**(items:={werkzeug.utils:None})})); saved.member=value',
])
def test_supported_literal_expansion_keys_remove_trust(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+statement)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter({**{"key":werkzeug}}.keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({**factory(werkzeug)}.keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({**holder}.keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({**{(werkzeug,):None}}.keys()))\nsaved[0]=value',
])
def test_value_objects_unknown_expansions_and_fresh_key_objects_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
