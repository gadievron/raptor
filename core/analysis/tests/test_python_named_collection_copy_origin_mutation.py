"""Named expressions preserve known collection origins before copying."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_named_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(items:=[werkzeug.utils]).copy().pop()', 'saved.secure_filename=replacement') is False


def test_named_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(items:={werkzeug.utils}).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('literal', ['[werkzeug.utils]','{werkzeug.utils}'])
def test_nested_named_collection_origins_remove_trust(literal):
    value=literal
    for index in range(32):
        value='(items'+str(index)+':='+value+')'
    source='import werkzeug\nsaved='+value+'.copy().pop()\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


def test_named_list_copy_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=(items:=[werkzeug.utils.__dict__]).copy().pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=(items:=holder).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(items:=factory(werkzeug)).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(items:=(werkzeug,)).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(items:={"key":werkzeug}).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(items:=[[werkzeug]]).copy().pop()\nsaved[0]=value',
    'import werkzeug\nsaved=(items:=[werkzeug]).copy()\nsaved[0]=value',
])
def test_unknown_origins_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
