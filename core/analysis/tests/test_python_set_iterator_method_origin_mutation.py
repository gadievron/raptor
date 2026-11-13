"""Set methods preserve members from recognised iterator wrappers."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_union_iterator_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.union(iter((werkzeug.utils,))).pop()', 'saved.secure_filename=replacement') is False


def test_set_symmetric_difference_reversed_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.symmetric_difference(reversed([werkzeug.utils])).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{None}.union(iter((werkzeug.utils,))).pop()',
    '{None}.symmetric_difference(reversed([werkzeug.utils])).pop()',
    '{None}.copy().union(iter([werkzeug.utils].copy())).copy().pop()',
    '{None}.union(iter(iter((werkzeug.utils,)))).pop()',
    '{werkzeug.utils}.difference(iter((None,))).pop()',
    '{werkzeug.utils}.intersection(reversed([werkzeug.utils])).pop()',
])
def test_set_method_iterator_member_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_imported_iterator_wrapper_alias_preserves_member_origin():
    source='import werkzeug\nfrom builtins import iter as iterate\nsaved={None}.union(iterate((werkzeug.utils,))).pop()\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={None}.union(iter(factory(werkzeug))).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union(iter((werkzeug,),sentinel)).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union(iter(iterable=(werkzeug,))).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.difference(iter((werkzeug,))).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.intersection(reversed([werkzeug])).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union(iter((werkzeug,)))\nsaved.member=value',
])
def test_unknown_sources_invalid_wrapper_shapes_operand_roles_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
