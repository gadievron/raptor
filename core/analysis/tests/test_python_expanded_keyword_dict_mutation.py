"""Expanded and named dictionary arguments both supply member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_named_expanded_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict(chosen=werkzeug.utils,**{})["chosen"]', 'saved.secure_filename=replacement') is False


def test_expanded_named_get_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict(**{"chosen":werkzeug.utils},other=None).get("chosen")', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'dict(chosen=werkzeug.utils,**{})["chosen"]',
    'dict(**{"chosen":werkzeug.utils},other=None)["chosen"]',
    'dict(**{},**{"chosen":werkzeug.utils})["chosen"]',
    'dict({},**{"chosen":werkzeug.utils})["chosen"]',
    'dict(werkzeug.__dict__,**{})["utils"]',
])
def test_mixed_dictionary_member_sources_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_expanded_named_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=dict(**{"chosen":werkzeug.utils.__dict__},other=None)["chosen"]\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=factory(chosen=werkzeug,**{})["chosen"]\nsaved.member=value',
    'import werkzeug\nsaved=dict(chosen=werkzeug,**{})\nsaved["chosen"]=value',
    'import werkzeug\nsaved=dict(**{"chosen":[werkzeug]},other=None)["chosen"]\nsaved[0]=value',
    'import werkzeug\nsaved=dict(**holder,other=None)["chosen"]\nsaved.member=value',
])
def test_unknown_factories_fresh_mappings_members_and_expansions_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
