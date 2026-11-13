"""Positional literal dictionary pairs retain iterated value references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_pair_list_values_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter(dict([("chosen",werkzeug.utils)]).values()))', 'saved.secure_filename=replacement') is False


def test_pair_tuple_values_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(dict((("chosen",werkzeug.utils),)).values())[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter(dict([("chosen",werkzeug.utils)]).values()))',
    'list(dict((("chosen",werkzeug.utils),)).values())[0]',
    'next(iter(dict([("chosen",werkzeug.utils)],other=None).values()))',
])
def test_positional_pair_values_iteration_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_positional_pair_values_keep_namespace_dictionary_kind():
    source='import werkzeug\nsaved=next(iter(dict([("chosen",werkzeug.utils.__dict__)]).values()))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter(dict([(werkzeug,holder)]).values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict([("key",werkzeug,None)]).values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict(**[("key",werkzeug)]).values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict([("key",[werkzeug])]).values()))\nsaved[0]=value',
    'import werkzeug\nsaved=next(iter(dict(factory(werkzeug)).values()))\nsaved.member=value',
])
def test_pair_keys_malformed_shapes_expanded_pairs_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
