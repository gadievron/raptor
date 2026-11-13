"""Set operators preserve known copied operand origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_set_union_operator_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=({werkzeug.utils}.copy() | {None}).pop()', 'saved.secure_filename=replacement') is False


def test_copied_set_subtraction_operator_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=({werkzeug.utils}.copy() - {None}).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '({werkzeug.utils}.copy() | {None}).pop()',
    '({None} | {werkzeug.utils}.copy()).pop()',
    '({werkzeug.utils}.copy() ^ {None}).pop()',
    '({None} ^ {werkzeug.utils}.copy()).pop()',
    '({werkzeug.utils}.copy() - {None}).pop()',
    '({werkzeug.utils}.copy() & {werkzeug.utils}).pop()',
    '(set((werkzeug.utils,)) | {None}.copy()).copy().pop()',
    '(({werkzeug.utils}.copy() | {None}) - {None}).pop()',
])
def test_known_set_operator_member_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=(factory(werkzeug) | {None}).pop()\nsaved.member=value',
    'import werkzeug\nsaved=([werkzeug].copy() | {None}).pop()\nsaved.member=value',
    'import werkzeug\nsaved=({None}.copy() - {werkzeug}).pop()\nsaved.member=value',
    'import werkzeug\nsaved=({None}.copy() & {werkzeug}).pop()\nsaved.member=value',
    'import werkzeug\nsaved=({werkzeug}.copy() + {None}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={werkzeug}.copy() | {None}\nsaved.member=value',
])
def test_unknown_operands_operand_roles_unsupported_operators_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
