"""Named copied receiver expressions retain exact getter collection origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_named_copied_dictionary_getter_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(copy:={"k":[werkzeug.utils]}.copy()).get("k").copy().pop()', 'saved.secure_filename=replacement') is False


def test_named_copied_sequence_getter_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(copy:=[[werkzeug.utils]].copy()).pop().copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '(copy:={"k":[werkzeug.utils]}.copy()).get("k").copy().pop()',
    '(copy:=[[werkzeug.utils]].copy()).pop().copy().pop()',
    '(copy:=[{werkzeug.utils}].copy()).__getitem__(0).copy().pop()',
    '(copy:=(inner:={"k":[werkzeug.utils]}.copy())).copy().pop("k").copy().pop()',
    '(copy:={}.copy()).setdefault("k",[werkzeug.utils]).copy().pop()',
])
def test_named_copied_exact_getter_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=(copy:=factory(werkzeug).copy()).get("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(copy:={"k":[werkzeug]}.copy(extra)).get("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(copy:=[[werkzeug]].copy()).pop(index).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(copy:={"k":None}.copy()).setdefault("k",[werkzeug]).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(copy:=[[werkzeug]].copy()).pop().copy()\nsaved[0]=value',
])
def test_unknown_results_invalid_shapes_selection_roles_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
