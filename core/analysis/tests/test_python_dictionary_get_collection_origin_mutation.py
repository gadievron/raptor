"""Exact literal dictionary get retains selected collection origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_dictionary_get_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":[werkzeug.utils]}.get("k").copy().pop()', 'saved.secure_filename=replacement') is False


def test_dictionary_get_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":{werkzeug.utils}}.get("k").copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{"k":[werkzeug.utils]}.get("k").copy().pop()',
    '{"k":{werkzeug.utils}}.get("k").copy().pop()',
    '{}.get("k",[werkzeug.utils]).copy().pop()',
    '{"k":None,"k":[werkzeug.utils]}.get("k").copy().pop()',
    '[{"k":[werkzeug.utils]}][0].get("k").copy().pop()',
    '{"k":[werkzeug.utils]}.get("k",None).copy().pop()',
])
def test_exact_dictionary_get_selected_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_dictionary_get_keeps_member_namespace_dictionary_kind():
    source='import werkzeug\nsaved={"k":[werkzeug.utils.__dict__]}.get("k").copy().pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={"k":[werkzeug]}.get(key).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.get("missing").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.get("missing",None).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug],"k":None}.get("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={**factory(werkzeug)}.get("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":(werkzeug,)}.get("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.get("k").copy()\nsaved[0]=value',
])
def test_unknown_or_missing_keys_default_roles_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_exact_get_collection_origin_retains_existing_iteration_uncertainty():
    source='import werkzeug\nfor saved in {"k":[None],"other":[werkzeug]}.get("k"):\n    saved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())
