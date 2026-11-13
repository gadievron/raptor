"""Bracket selection from shallow copies retains known collection origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_list_subscript_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[[werkzeug.utils]].copy()[0].copy().pop()', 'saved.secure_filename=replacement') is False


def test_copied_dictionary_subscript_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":[werkzeug.utils]}.copy()["k"].copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[[werkzeug.utils]].copy()[0].copy().pop()',
    '{"k":[werkzeug.utils]}.copy()["k"].copy().pop()',
    '[None,{werkzeug.utils}].copy()[-1].copy().pop()',
    '(copy:={"k":[werkzeug.utils]}.copy())["k"].copy().pop()',
    '{"k":None,"k":[werkzeug.utils]}.copy()["k"].copy().pop()',
])
def test_copied_literal_subscript_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=[[werkzeug]].copy()[index].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].copy()[1].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].copy()[True].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.copy()["missing"].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug],"k":None}.copy()["k"].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug).copy()[0].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].copy()[0].copy()\nsaved[0]=value',
])
def test_unknown_indices_and_receivers_selection_roles_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
