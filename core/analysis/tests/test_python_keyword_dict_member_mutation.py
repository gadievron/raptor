"""Named dictionary constructor values retain shared object identity."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_keyword_dictionary_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict(chosen=werkzeug.utils)["chosen"]', 'saved.secure_filename=replacement') is False


def test_keyword_dictionary_get_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict(chosen=werkzeug.utils).get("chosen")', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'dict(chosen=werkzeug.utils)["chosen"]',
    'dict(other=None,chosen=werkzeug.utils).get("chosen")',
    'dict(chosen=werkzeug.utils).__getitem__("chosen")',
])
def test_keyword_constructor_member_references_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_keyword_constructor_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=dict(chosen=werkzeug.utils.__dict__)["chosen"]\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


def test_absolute_builtin_dictionary_alias_keeps_keyword_member():
    source='import werkzeug\nfrom builtins import dict as build\nsaved=build(chosen=werkzeug.utils)["chosen"]\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=factory(chosen=werkzeug)["chosen"]\nsaved.member=value',
    'import werkzeug\nsaved=dict(chosen=werkzeug)\nsaved["chosen"]=value',
    'import werkzeug\nsaved=dict(chosen=[werkzeug])["chosen"]\nsaved[0]=value',
    'import werkzeug\nsaved=dict(chosen=holder)["chosen"]\nsaved.member=value',
])
def test_unknown_factories_fresh_mapping_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
