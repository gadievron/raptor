"""Nested copied/selected receiver graphs preserve exact getter origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_nested_copied_dictionary_receiver_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[{"k":[werkzeug.utils]}].copy()[0].get("k").copy().pop()', 'saved.secure_filename=replacement') is False


def test_nested_copied_sequence_receiver_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[[[werkzeug.utils]]].copy()[0].pop().copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[{"k":[werkzeug.utils]}].copy()[0].get("k").copy().pop()',
    '[[[werkzeug.utils]]].copy()[0].pop().copy().pop()',
    '{"chosen":{"k":[werkzeug.utils]}}.copy()["chosen"].get("k").copy().pop()',
    '[None,[[werkzeug.utils]]].copy()[-1].__getitem__(0).copy().pop()',
    '[(copy:={"k":[werkzeug.utils]}.copy())].copy()[0].get("k").copy().pop()',
])
def test_nested_copy_receiver_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=[factory(werkzeug)].copy()[0].get("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[{"k":[werkzeug]}].copy()[index].get("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[[werkzeug]]].copy()[1].pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[{"k":None}].copy()[0].setdefault("k",[werkzeug]).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[[werkzeug]]].copy()[0].pop().copy()\nsaved[0]=value',
])
def test_unknown_nodes_selection_roles_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
