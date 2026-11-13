"""Named expressions preserve supported set origins for popped members."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_named_set_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(items:={werkzeug.utils}).pop()', 'saved.secure_filename=replacement') is False


def test_named_set_operation_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(items:=({werkzeug.utils}|{werkzeug.utils})).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '(items:={werkzeug.utils}).pop()',
    '(items:=({werkzeug.utils}|{werkzeug.utils})).pop()',
    '(outer:=(inner:={werkzeug.utils}.union())).pop()',
    '(items:={"key":werkzeug.utils}).pop("key")',
])
def test_named_set_and_existing_dictionary_pop_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=(items:=holder).pop()\nsaved.member=value',
    'import werkzeug\nsaved=(items:=factory(werkzeug)).pop()\nsaved.member=value',
    'import werkzeug\nsaved=(items:={(werkzeug,)}).pop()\nsaved[0]=value',
    'import werkzeug\nsaved=(items:={werkzeug})\nsaved.clear()',
    'import werkzeug\nsaved=(items:={werkzeug}).pop(0)\nsaved.member=value',
])
def test_unknown_origins_fresh_members_and_invalid_set_pop_shapes_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
