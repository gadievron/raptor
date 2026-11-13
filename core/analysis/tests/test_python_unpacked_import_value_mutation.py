"""Literal unpacking can save a shared imported object for later mutation."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_unpacked_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved,other=(werkzeug.utils,None)',
                       'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('binding', [
    'saved,other=(werkzeug.utils,None)',
    '[other,saved]=[None,werkzeug.utils]',
    '(other,(saved,))=(None,(werkzeug.utils,))',
    'saved,other=(globals()["werkzeug"].utils,None)',
])
def test_literal_unpacked_import_mutation_removes_trust(binding):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+binding+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved,other=(werkzeug.utils,None)',
    'import werkzeug\nother,saved=(werkzeug.utils,None)\nsaved.member=value',
    'import werkzeug\nsaved,other=factory(werkzeug)\nsaved.member=value',
    'import werkzeug\nsaved,*other=(werkzeug.utils,None)\nsaved.member=value',
    'import werkzeug\nsaved,other=(werkzeug.utils,)\nsaved.member=value',
    'import werkzeug\nsaved,other=holder[werkzeug]\nsaved.member=value',
])
def test_unused_unpacked_imports_and_unresolved_values_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
