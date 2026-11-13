"""Literal dictionary setdefault retains the selected collection result origin."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_dictionary_setdefault_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"k":[werkzeug.utils]}.setdefault("k").copy().pop()', 'saved.secure_filename=replacement') is False


def test_dictionary_setdefault_set_default_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={}.setdefault("k",{werkzeug.utils}).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{"k":[werkzeug.utils]}.setdefault("k").copy().pop()',
    '{}.setdefault("k",{werkzeug.utils}).copy().pop()',
    '{}.setdefault("k",[werkzeug.utils]).copy().pop()',
    '{"k":None,"k":[werkzeug.utils]}.setdefault("k").copy().pop()',
    '{"k":[werkzeug.utils]}.setdefault("k",None).copy().pop()',
])
def test_exact_dictionary_setdefault_selected_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={"k":None}.setdefault("k",[werkzeug]).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.setdefault("missing").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.setdefault(key).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug],"k":None}.setdefault("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={**factory(werkzeug)}.setdefault("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":(werkzeug,)}.setdefault("k").copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={"k":[werkzeug]}.setdefault("k").copy()\nsaved[0]=value',
])
def test_existing_keys_default_roles_unknowns_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
