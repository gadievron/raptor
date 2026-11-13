"""Named-expression wrappers preserve exact imported alias values."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_wrapped_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('outer=(inner:=werkzeug.utils)',
                       'outer.secure_filename=replacement') is False


@pytest.mark.parametrize('binding', [
    'outer=(inner:=werkzeug.utils)',
    'outer=(first:=(second:=werkzeug.utils))',
    'outer=(inner:=globals()["werkzeug"].utils)',
    'outer=(inner:=werkzeug).utils',
])
def test_wrapped_import_value_mutations_remove_namespace_trust(binding):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+binding+'\nouter.member=value')) == (True, frozenset())


@pytest.mark.parametrize('binding', [
    'outer=(inner:=factory(werkzeug))',
    'outer=holder[(inner:=werkzeug)]',
])
def test_wrapped_unresolved_calls_and_keys_keep_existing_behavior(binding):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+binding+'\nouter.member=value')) == (False, frozenset())
