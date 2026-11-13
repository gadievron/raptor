"""Comprehension-local values can mutate shared imported objects."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_comprehension_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('[saved.__setattr__("secure_filename",replacement) for saved in (werkzeug.utils,)]', 'pass') is False


@pytest.mark.parametrize('expression', [
    '[saved.__setattr__("member",value) for saved in (werkzeug.utils,)]',
    '{saved.__setattr__("member",value) for saved in [werkzeug.utils]}',
    '{key:saved.__setattr__("member",value) for saved,key in [(werkzeug.utils,1)]}',
    '(saved.__setattr__("member",value) for saved in (werkzeug.utils,))',
])
def test_literal_comprehension_mutations_remove_trust(expression):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+expression)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\n[saved.member for saved in (werkzeug.utils,)]',
    'import werkzeug\n[saved.__setattr__("member",value) for saved in factory(werkzeug)]',
    'import werkzeug\ndef handle():\n    value: [saved.__setattr__("member",value) for saved in (werkzeug.utils,)]',
])
def test_comprehension_reads_unresolved_iterators_and_local_annotations_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
