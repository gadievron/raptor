"""Exact dictionary getitem preserves selected collection origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_dictionary_getitem_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":[werkzeug.utils]}.__getitem__("k").copy().pop()', 'saved.secure_filename=replacement') is False


def test_dictionary_getitem_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":{werkzeug.utils}}.__getitem__("k").copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{"k":[werkzeug.utils]}.__getitem__("k").copy().pop()',
    '{"k":{werkzeug.utils}}.__getitem__("k").copy().pop()',
    '{"k":None,"k":[werkzeug.utils]}.__getitem__("k").copy().pop()',
    '[{"k":[werkzeug.utils]}][0].__getitem__("k").copy().pop()',
])
def test_exact_dictionary_getitem_selected_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_dictionary_getitem_retains_existing_iteration_uncertainty():
    source='import werkzeug\nfor saved in {"k":[None],"other":[werkzeug]}.__getitem__("k"):\n    saved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={"k":[werkzeug]}.__getitem__(key).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.__getitem__("missing").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.__getitem__("k",[]).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.__getitem__(key="k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={**factory(werkzeug)}.__getitem__("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":(werkzeug,)}.__getitem__("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.__getitem__("k").copy()\nsaved[0]=value',
])
def test_unknown_or_missing_keys_invalid_shapes_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
