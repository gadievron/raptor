"""Reflected and conditional namespace dictionary aliases remain mutable."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_reflected_dictionary_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=getattr(werkzeug.utils,"__dict__")',
                       'saved.update({"secure_filename":replacement})') is False


def test_conditional_dictionary_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=werkzeug.utils.__dict__ if raw else werkzeug.utils.__dict__',
                       'saved.update({"secure_filename":replacement})') is False


@pytest.mark.parametrize('binding', [
    'saved=getattr(werkzeug.utils,"__dict__")',
    'saved=werkzeug.utils.__dict__ if condition else None',
    'saved=condition and werkzeug.utils.__dict__',
    'from builtins import vars as namespace\nsaved=namespace(werkzeug.utils)',
])
def test_possible_dictionary_alias_mutations_remove_trust(binding):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+binding+'\nsaved.update(value)')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=getattr(werkzeug.utils,"__dict__")',
    'import werkzeug\nsaved=werkzeug.utils.__dict__ if condition else None',
    'import werkzeug\nsaved=getattr(holder,"__dict__")\nsaved.update(value)',
    'import werkzeug\nsaved=first if werkzeug.utils.__dict__ else second\nsaved.update(value)',
])
def test_reads_unrelated_objects_and_conditions_keep_existing_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
