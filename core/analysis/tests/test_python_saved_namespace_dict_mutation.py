"""Saved imported namespace dictionaries retain mutation uncertainty."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_saved_namespace_dict_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=werkzeug.utils.__dict__',
                       'saved.update({"secure_filename":replacement})') is False


@pytest.mark.parametrize('method', ['update', 'clear', 'pop', 'popitem', 'setdefault',
                                    '__setitem__', '__delitem__', '__ior__', '__init__'])
def test_saved_namespace_dict_mutators_remove_trust(method):
    source='import werkzeug\nsaved=werkzeug.utils.__dict__\nsaved.'+method+'(value)'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=werkzeug.utils.__dict__',
    'import werkzeug\nsaved=werkzeug.utils.__dict__\nsaved.get("field")',
    'import werkzeug\nsaved=werkzeug.utils.__dict__\nsaved.copy()',
    'import werkzeug\nsaved=holder.__dict__\nsaved.update(value)',
    'import werkzeug\nsaved=factory(werkzeug).__dict__\nsaved.update(value)',
])
def test_saved_namespace_reads_and_unresolved_objects_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_wrapped_chained_dictionary_aliases_remove_trust_on_mutation():
    source='import werkzeug\nfirst=second=(inner:=werkzeug.utils.__dict__)\nsecond.update(value)'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())
