"""Set algebra methods consume dictionary keys without exposing values."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_union_dictionary_key_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.union({werkzeug.utils:None}).pop()', 'saved.secure_filename=replacement') is False


def test_set_symmetric_difference_dictionary_key_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.symmetric_difference({werkzeug.utils:None}).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{None}.union({werkzeug.utils:None}).pop()',
    '{None}.symmetric_difference({werkzeug.utils:None}).pop()',
    '{None}.copy().union({werkzeug.utils:None}).copy().pop()',
    '{None}.union({**{werkzeug.utils:None}}).pop()',
    '{werkzeug.utils}.difference({None:0}).pop()',
    '{werkzeug.utils}.intersection({werkzeug.utils:None}).pop()',
])
def test_set_method_dictionary_key_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={None}.union({None:werkzeug}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.symmetric_difference({None:werkzeug}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union({**factory(werkzeug)}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.difference({werkzeug:None}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.intersection({werkzeug:None}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.symmetric_difference({werkzeug:None},{}).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union({werkzeug:None})\nsaved.member=value',
])
def test_dictionary_values_unknown_expansions_operand_roles_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
