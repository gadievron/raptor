"""Same-kind possible collection results retain known origins before copying."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_conditional_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([werkzeug.utils] if raw else [werkzeug.utils]).copy().pop()', 'saved.secure_filename=replacement') is False


def test_boolean_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=({werkzeug.utils} or {None}).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '([werkzeug.utils] if raw else []).copy().pop()',
    '([] or [werkzeug.utils]).copy().pop()',
    '({werkzeug.utils} if raw else {*[]}).copy().pop()',
    '(items:=([werkzeug.utils] if raw else [])).copy().pop()',
])
def test_same_kind_possible_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_conditional_list_copy_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=([werkzeug.utils.__dict__] if raw else []).copy().pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=([holder] if werkzeug else [other]).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=(factory(werkzeug) if raw else holder).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=([[werkzeug]] if raw else []).copy().pop()\nsaved[0]=value',
    'import werkzeug\nsaved=([werkzeug] if raw else []).copy()\nsaved[0]=value',
    'import werkzeug\nsaved=((werkzeug,) if raw else ()).copy().pop()\nsaved.member=value',
])
def test_conditions_unknown_origins_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
