"""Conditional expressions can return shared imported mutation receivers."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_conditional_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=werkzeug.utils if raw else werkzeug.utils',
                       'saved.secure_filename=replacement') is False


def test_boolean_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=werkzeug.utils or werkzeug.utils',
                       'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'werkzeug.utils if condition else None',
    'None if condition else werkzeug.utils',
    'condition and werkzeug.utils',
    'werkzeug.utils or fallback',
    '(werkzeug.utils if condition else None).child',
])
def test_possible_import_result_mutations_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=replacement')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=werkzeug.utils if condition else None',
    'import werkzeug\nsaved=first if werkzeug else second\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug) or fallback\nsaved.member=value',
    'import werkzeug\ndef handle():\n    value: (werkzeug.utils if condition else None)',
])
def test_reads_conditions_and_unresolved_results_keep_existing_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
