"""Supported literal set operation results retain popped member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_union_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=({werkzeug.utils}|{werkzeug.utils}).pop()', 'saved.secure_filename=replacement') is False


def test_set_method_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={werkzeug.utils}.difference({None}).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '({werkzeug.utils}|{werkzeug.utils}).pop()',
    '({werkzeug.utils}&{werkzeug.utils}).pop()',
    '({werkzeug.utils}-{None}).pop()',
    '({werkzeug.utils}^{*[]}).pop()',
    '{werkzeug.utils}.union().pop()',
    '{werkzeug.utils}.intersection({werkzeug.utils}).pop()',
    '{werkzeug.utils}.symmetric_difference({*[]}).pop()',
])
def test_supported_set_operation_pop_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=({None}-{werkzeug}).pop()\nsaved.member=value',
    'import werkzeug\nsaved=({werkzeug}|holder).pop()\nsaved.member=value',
    'import werkzeug\nsaved={werkzeug}.union(holder).pop()\nsaved.member=value',
    'import werkzeug\nsaved=({(werkzeug,)}-{None}).pop()\nsaved[0]=value',
    'import werkzeug\nsaved={werkzeug}.union()\nsaved.clear()',
    'import werkzeug\nsaved=({werkzeug}|{werkzeug}).pop(0)\nsaved.member=value',
])
def test_unknown_operands_subset_sources_fresh_containers_and_invalid_pop_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
