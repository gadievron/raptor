"""Zero-argument vars uses local keys inside functions."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_local_vars_value_write_cannot_preserve_shared_callable_identity():
    assert suppression('import werkzeug as local_module',
                       'vars()["local_module"].utils.secure_filename=replacement') is False


@pytest.mark.parametrize('statement', [
    'vars()["alias"].member=replacement',
    'del vars()["alias"].member',
    'setattr(vars()["alias"],"member",replacement)',
    'saved=vars()["alias"].__setattr__',
    'vars()["alias"].__dict__.update(values)',
])
def test_function_local_vars_value_writes_remove_whole_trust(statement):
    assert module_dynamic_namespace(ast.parse('def handle():\n    '+statement)) == (True, frozenset())


@pytest.mark.parametrize('statement', [
    'saved=vars()["alias"].member',
    'value: vars()["alias"].member',
])
def test_local_vars_reads_and_annotations_keep_existing_behavior(statement):
    assert module_dynamic_namespace(ast.parse('def handle():\n    '+statement)) == (False, frozenset())


def test_module_vars_write_still_poison_only_the_named_root():
    assert module_dynamic_namespace(ast.parse('vars()["root"].member=value')) == (False, frozenset({'root'}))
