"""Sequence constructors retain references from explicit literal sequences."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_list_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list((werkzeug.utils,))[0]', 'saved.secure_filename=replacement') is False


def test_tuple_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=tuple([werkzeug.utils])[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list((werkzeug.utils,))[0]',
    'tuple([werkzeug.utils])[0]',
    'list([werkzeug.utils][:])[0]',
    'tuple([werkzeug.utils]).__getitem__(0)',
])
def test_literal_sequence_constructor_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_absolute_builtin_sequence_alias_retains_member_reference():
    source='import werkzeug\nfrom builtins import list as sequence\nsaved=sequence((werkzeug.utils,))[0]\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list((werkzeug.utils,))\nsaved[0]=value',
    'import werkzeug\nsaved=tuple([werkzeug.utils])\nsaved.member=value',
    'import werkzeug\nsaved=list(factory(werkzeug))[0]\nsaved.member=value',
    'import werkzeug\nsaved=tuple(holder)[0]\nsaved.member=value',
])
def test_fresh_sequence_writes_and_arbitrary_iterators_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_constructor_alias_collision_preserves_dictionary_pair_projection():
    source='import werkzeug\nfrom builtins import dict as list\nsaved=list([("utils",werkzeug.utils)])["utils"]\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())
