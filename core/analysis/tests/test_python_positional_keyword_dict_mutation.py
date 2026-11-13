"""Dictionary source and keyword arguments both supply member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_positional_keyword_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict({},chosen=werkzeug.utils)["chosen"]', 'saved.secure_filename=replacement') is False


def test_positional_keyword_get_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict({},chosen=werkzeug.utils).get("chosen")', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'dict({},chosen=werkzeug.utils)["chosen"]',
    'dict({"chosen":werkzeug.utils},other=None)["chosen"]',
    'dict([("chosen",werkzeug.utils)],other=None)["chosen"]',
    'dict(werkzeug.__dict__,other=None)["utils"]',
])
def test_positional_and_keyword_member_sources_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_positional_keyword_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=dict({},chosen=werkzeug.utils.__dict__)["chosen"]\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=factory({},chosen=werkzeug)["chosen"]\nsaved.member=value',
    'import werkzeug\nsaved=dict({},chosen=werkzeug)\nsaved["chosen"]=value',
    'import werkzeug\nsaved=dict({},chosen=[werkzeug])["chosen"]\nsaved[0]=value',
    'import werkzeug\nsaved=dict([(werkzeug,holder)],chosen=None)["chosen"]\nsaved.member=value',
])
def test_unknown_factories_fresh_mappings_members_and_pair_keys_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
