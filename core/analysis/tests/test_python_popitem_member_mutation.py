"""Literal dictionary popitem pairs retain existing key/value references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_popitem_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"chosen":werkzeug.utils}.popitem()[1]', 'saved.secure_filename=replacement') is False


def test_popitem_getitem_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"chosen":werkzeug.utils}.popitem().__getitem__(1)', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{"chosen":werkzeug.utils}.popitem()[1]',
    '{werkzeug.utils:None}.popitem()[0]',
    '[{"chosen":werkzeug.utils}][0].popitem()[1]',
])
def test_popitem_pair_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_popitem_member_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved={"chosen":werkzeug.utils.__dict__}.popitem()[1]\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=holder.popitem()[1]\nsaved.member=value',
    'import werkzeug\nsaved={"chosen":werkzeug}.popitem()\nsaved[1]=value',
    'import werkzeug\nsaved={"chosen":[werkzeug]}.popitem()[1]\nsaved[0]=value',
    'import werkzeug\nsaved={"chosen":werkzeug}.popitem(0)[1]\nsaved.member=value',
])
def test_unknown_methods_fresh_pair_and_fresh_member_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
