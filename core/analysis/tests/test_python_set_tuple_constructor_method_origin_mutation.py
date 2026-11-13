"""Set methods preserve member origins from explicit tuple construction."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_union_tuple_constructor_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.union(tuple((werkzeug.utils,))).pop()', 'saved.secure_filename=replacement') is False


def test_set_symmetric_difference_tuple_constructor_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.symmetric_difference(tuple([werkzeug.utils])).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{None}.union(tuple((werkzeug.utils,))).pop()',
    '{None}.symmetric_difference(tuple([werkzeug.utils])).pop()',
    '{None}.union(tuple(iter((werkzeug.utils,)))).copy().pop()',
    '{None}.union(tuple(tuple((werkzeug.utils,)))).pop()',
    '{None}.union(tuple({werkzeug.utils:None})).pop()',
    '{werkzeug.utils}.difference(tuple((None,))).pop()',
    '{werkzeug.utils}.intersection(tuple([werkzeug.utils])).pop()',
])
def test_set_method_tuple_constructor_member_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_builtin_tuple_alias_preserves_member_origin():
    source='import werkzeug\nfrom builtins import tuple as make_tuple\nsaved={None}.union(make_tuple((werkzeug.utils,))).pop()\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={None}.union(tuple(factory(werkzeug))).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union(tuple((werkzeug,),extra)).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union(tuple(iterable=(werkzeug,))).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union(tuple({None:werkzeug})).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.difference(tuple((werkzeug,))).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.intersection(tuple([werkzeug])).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union(tuple((werkzeug,)))\nsaved.member=value',
])
def test_unknown_sources_invalid_constructor_shapes_roles_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
