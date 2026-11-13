"""Possible literal list result operands retain popped member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_conditional_list_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([werkzeug.utils] if raw else [werkzeug.utils]).pop()', 'saved.secure_filename=replacement') is False


def test_boolean_list_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([werkzeug.utils] or []).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '([werkzeug.utils] if raw else holder).pop()',
    '(holder or [werkzeug.utils]).pop()',
    '(items:=([werkzeug.utils] if raw else holder)).pop()',
    '({None} if raw else [werkzeug.utils]).pop()',
])
def test_supported_literal_list_result_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_conditional_list_pop_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=([werkzeug.utils.__dict__] if raw else holder).pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=([holder] if werkzeug else other).pop()\nsaved.member=value',
    'import werkzeug\nsaved=(factory(werkzeug) if raw else holder).pop()\nsaved.member=value',
    'import werkzeug\nsaved=([[werkzeug]] if raw else holder).pop()\nsaved[0]=value',
    'import werkzeug\nsaved=([werkzeug] if raw else holder)\nsaved[0]=value',
    'import werkzeug\nsaved=((werkzeug,) if raw else holder).pop()\nsaved.member=value',
])
def test_conditions_unknown_origins_fresh_members_and_tuple_shapes_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
