"""Shallow dictionary copies preserve exact getter collection result origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_dictionary_get_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":[werkzeug.utils]}.copy().get("k").copy().pop()', 'saved.secure_filename=replacement') is False


def test_copied_dictionary_pop_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":{werkzeug.utils}}.copy().pop("k").copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{"k":[werkzeug.utils]}.copy().get("k").copy().pop()',
    '{"k":{werkzeug.utils}}.copy().pop("k").copy().pop()',
    '{"k":[werkzeug.utils]}.copy().copy().__getitem__("k").copy().pop()',
    '{}.copy().setdefault("k",[werkzeug.utils]).copy().pop()',
    '[{"k":[werkzeug.utils]}][0].copy().get("k").copy().pop()',
])
def test_copied_dictionary_exact_getter_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=factory(werkzeug).copy().get("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.copy(extra).get("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.copy().get(key).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.copy().get("missing").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":None}.copy().setdefault("k",[werkzeug]).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.copy().get("k").copy()\nsaved[0]=value',
])
def test_unknown_copies_invalid_shapes_selection_roles_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
