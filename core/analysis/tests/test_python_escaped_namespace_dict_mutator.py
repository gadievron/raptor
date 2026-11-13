"""Escaped namespace dictionary mutators invalidate callable trust."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_escaped_namespace_mutator_cannot_preserve_replaced_callable_identity():
    assert suppression('edit=werkzeug.utils.__dict__.update',
                       'edit({"secure_filename":replacement})') is False


@pytest.mark.parametrize('source,expected', [
    ('import werkzeug\nsaved=werkzeug.utils.__dict__.clear', (True, frozenset())),
    ('import werkzeug\ndictionary=werkzeug.utils.__dict__\nsaved=dictionary.update', (True, frozenset())),
    ('saved=globals()["root"].__dict__.update', (False, frozenset({'root'}))),
    ('def handle():\n    saved=locals()["root"].__dict__.clear', (True, frozenset())),
])
def test_escaped_dictionary_capabilities_remove_matching_trust(source, expected):
    assert module_dynamic_namespace(ast.parse(source)) == expected


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=werkzeug.utils.__dict__.get',
    'import werkzeug\nsaved=werkzeug.utils.__dict__.copy',
    'import werkzeug\nsaved=werkzeug.utils.__dict__.__or__',
    'import werkzeug\nsaved=holder.__dict__.update',
    'import werkzeug\ndef handle():\n    value: werkzeug.utils.__dict__.update',
])
def test_read_capabilities_unrelated_objects_and_annotations_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
