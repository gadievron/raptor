"""Namespace dictionary getters may return shared imported objects."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_dictionary_member_result_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=werkzeug.__dict__.get("utils")',
                       'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'werkzeug.__dict__.get("utils")',
    'werkzeug.__dict__.__getitem__("utils")',
    'vars(werkzeug).get("utils")',
    'getattr(werkzeug,"__dict__").get("utils")',
    'holder.__dict__.get("field",werkzeug.utils)',
])
def test_possible_dictionary_member_mutations_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=replacement')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=werkzeug.__dict__.get("utils")',
    'import werkzeug\nsaved=holder.__dict__.get("member")\nsaved.member=value',
    'import werkzeug\nsaved=werkzeug.get("member")\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug).get("member")\nsaved.member=value',
])
def test_unused_reads_and_unresolved_mappings_keep_existing_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
