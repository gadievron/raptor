"""Local namespace values can expose shared imported objects."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_local_lookup_mutation_cannot_preserve_shared_callable_identity():
    assert suppression('import werkzeug as local_module',
                       'locals()["local_module"].utils.secure_filename=replacement') is False


@pytest.mark.parametrize('statement', [
    'locals()["alias"].member=replacement',
    'del locals()["alias"].member',
    'setattr(locals()["alias"],"member",replacement)',
    'saved=locals()["alias"].__setattr__',
    'locals()["alias"].__dict__.update(values)',
])
def test_local_value_mutations_remove_namespace_trust(statement):
    assert module_dynamic_namespace(ast.parse('def handle():\n    '+statement)) == (True, frozenset())


@pytest.mark.parametrize('statement', [
    'locals()["alias"]=replacement',
    'del locals()["alias"]',
    'saved=locals()["alias"].member',
    'saved=locals()',
    'value: locals()["alias"].member',
])
def test_local_mapping_bindings_and_inert_reads_keep_existing_behavior(statement):
    assert module_dynamic_namespace(ast.parse('def handle():\n    '+statement)) == (False, frozenset())
