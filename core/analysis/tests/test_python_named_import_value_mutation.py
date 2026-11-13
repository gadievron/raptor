"""Named-expression import aliases remain visible to mutation checks."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_named_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('(saved:=werkzeug.utils)', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('binding', [
    '(saved:=werkzeug.utils)',
    'if saved:=werkzeug.utils: pass',
    '(saved:=globals()["werkzeug"].utils)',
])
def test_named_import_alias_mutation_removes_namespace_trust(binding):
    source='import werkzeug\n'+binding+'\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\n(saved:=werkzeug.utils)',
    'import werkzeug\n(saved:=factory(werkzeug))\nsaved.member=value',
    'import werkzeug\n(saved:=holder[werkzeug])\nsaved.member=value',
    'import werkzeug\ndef handle():\n    value: (saved:=werkzeug.utils)',
])
def test_unused_named_aliases_and_unresolved_positions_preserve_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
