"""Literal dictionary pop retains the selected collection result origin."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_dictionary_pop_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":[werkzeug.utils]}.pop("k").copy().pop()', 'saved.secure_filename=replacement') is False


def test_dictionary_pop_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":{werkzeug.utils}}.pop("k").copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{"k":[werkzeug.utils]}.pop("k").copy().pop()',
    '{"k":{werkzeug.utils}}.pop("k").copy().pop()',
    '{}.pop("k",[werkzeug.utils]).copy().pop()',
    '{"k":None,"k":[werkzeug.utils]}.pop("k").copy().pop()',
    '[{"k":[werkzeug.utils]}][0].pop("k").copy().pop()',
])
def test_exact_dictionary_pop_selected_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={"k":[werkzeug]}.pop(key).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.pop("missing").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.pop("missing",None).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug],"k":None}.pop("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={**factory(werkzeug)}.pop("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":(werkzeug,)}.pop("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.pop("k").copy()\nsaved[0]=value',
])
def test_unknown_keys_default_roles_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
