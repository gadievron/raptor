"""Explicit iteration retains members of literal getter result sequences."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_get_sequence_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({"chosen":[werkzeug.utils]}.get("chosen")))', 'saved.secure_filename=replacement') is False


def test_getitem_sequence_copy_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list({"chosen":[werkzeug.utils]}.__getitem__("chosen"))[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter({"chosen":[werkzeug.utils]}.get("chosen")))',
    'tuple([[werkzeug.utils]].__getitem__(0))[0]',
    'list({}.get("missing",[werkzeug.utils]))[0]',
    'next(iter([{ "chosen":[werkzeug.utils]}][0].get("chosen")))',
])
def test_literal_getter_sequence_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_literal_getter_sequence_keeps_dictionary_kind():
    source='import werkzeug\nsaved=next(iter({"chosen":[werkzeug.utils.__dict__]}.get("chosen")))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list(holder.get(werkzeug))[0]\nsaved.member=value',
    'import werkzeug\nsaved=list({werkzeug:holder}.get("chosen"))[0]\nsaved.member=value',
    'import werkzeug\nsaved=list({"chosen":factory(werkzeug)}.get("chosen"))[0]\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({"chosen":[[werkzeug.utils]]}.get("chosen")))\nsaved[0]=value',
])
def test_unknown_getter_origins_keys_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
