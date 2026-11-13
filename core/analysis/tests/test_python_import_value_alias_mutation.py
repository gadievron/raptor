"""Saved imported values remain visible to mutation refusal."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_saved_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=werkzeug.utils', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=werkzeug.utils\ndel saved.secure_filename',
    'import werkzeug\nsaved=werkzeug.utils\nsetattr(saved,"secure_filename",replacement)',
    'import werkzeug\nsaved: object=werkzeug.utils\nsaved.__dict__.update(values)',
    'import werkzeug\na=b=werkzeug.utils\nb.secure_filename=value',
])
def test_direct_saved_import_mutations_remove_trust(source):
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=werkzeug.utils',
    'import werkzeug\nsaved=werkzeug.utils\nvalue=saved.member',
    'import werkzeug\nsaved=holder[werkzeug]\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug)\nsaved.member=value',
    'import werkzeug\ndef handle():\n    saved: werkzeug.utils',
])
def test_unused_saved_imports_and_unresolved_positions_preserve_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
