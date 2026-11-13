"""Known set receiver origins survive guarded algebra method calls."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_set_union_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={werkzeug.utils}.copy().union({None}).pop()', 'saved.secure_filename=replacement') is False


def test_copied_set_difference_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={werkzeug.utils}.copy().difference({None}).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{werkzeug.utils}.copy().union({None}).pop()',
    '{werkzeug.utils}.copy().difference({None}).pop()',
    '{werkzeug.utils}.copy().intersection({werkzeug.utils}).pop()',
    '{werkzeug.utils}.copy().symmetric_difference({None}).pop()',
    'set((werkzeug.utils,)).union({None}).copy().pop()',
    '({werkzeug.utils} if flag else {None}).union({None}).pop()',
    '{None}.copy().union({werkzeug.utils}).pop()',
    '{None}.copy().symmetric_difference({werkzeug.utils}).pop()',
])
def test_known_set_receiver_method_member_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=factory(werkzeug).union({None}).pop()\nsaved.member=value',
    'import werkzeug\nsaved=[werkzeug].copy().union({None}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.copy().difference({werkzeug}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.copy().intersection({werkzeug}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.copy().symmetric_difference({werkzeug},{None}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={werkzeug}.copy().union(other={None}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={werkzeug}.copy().union({None})\nsaved.member=value',
])
def test_unknown_receivers_operand_roles_invalid_shapes_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
