"""Direct aliases of imported namespace values retain mutation uncertainty."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_saved_global_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=globals()["werkzeug"].utils',
                       'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=globals()["werkzeug"].utils\ndel saved.secure_filename',
    'import werkzeug\nsaved=globals()["werkzeug"].utils\nsetattr(saved,"secure_filename",replacement)',
    'import werkzeug\nsaved: object=globals()["werkzeug"].utils\nsaved.__dict__.update(values)',
    'import werkzeug\na=b=globals()["werkzeug"].utils\nb.secure_filename=value',
])
def test_direct_saved_namespace_value_mutation_removes_trust(source):
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=globals()["werkzeug"].utils',
    'import werkzeug\nsaved=globals()["werkzeug"].utils\nvalue=saved.member',
    'import werkzeug\nsaved=holder[globals()["werkzeug"]]\nsaved.member=value',
    'import werkzeug\nsaved=factory(globals()["werkzeug"])\nsaved.member=value',
    'import werkzeug\ndef handle():\n    saved: globals()["werkzeug"].utils',
])
def test_reads_and_unresolved_value_positions_keep_existing_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
