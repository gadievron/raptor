"""Set algebra methods retain members of explicit iterable arguments."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_union_tuple_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.union((werkzeug.utils,)).pop()', 'saved.secure_filename=replacement') is False


def test_set_symmetric_difference_list_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.symmetric_difference([werkzeug.utils]).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{None}.union((werkzeug.utils,)).pop()',
    '{None}.symmetric_difference([werkzeug.utils]).pop()',
    '{None}.copy().union([werkzeug.utils]).copy().pop()',
    '{werkzeug.utils}.difference((None,)).pop()',
    '{werkzeug.utils}.intersection([werkzeug.utils]).pop()',
    '{None}.union((None,),[werkzeug.utils]).pop()',
    '{None}.union([*(werkzeug.utils,)]).pop()',
])
def test_set_method_literal_iterable_member_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={None}.union(factory(werkzeug)).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.difference((werkzeug,)).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.intersection([werkzeug]).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.symmetric_difference([werkzeug],[]).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union(other=[werkzeug]).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union([werkzeug])\nsaved.member=value',
])
def test_unknown_iterables_operand_roles_invalid_shapes_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
