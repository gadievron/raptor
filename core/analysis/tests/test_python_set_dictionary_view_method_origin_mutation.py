"""Set methods preserve supported dictionary view iterable origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_union_dictionary_values_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.union({"k":werkzeug.utils}.values()).pop()', 'saved.secure_filename=replacement') is False


def test_set_symmetric_difference_dictionary_keys_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={None}.symmetric_difference({werkzeug.utils:None}.keys()).pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{None}.union({"k":werkzeug.utils}.values()).pop()',
    '{None}.symmetric_difference({werkzeug.utils:None}.keys()).pop()',
    '{None}.union(dict(k=werkzeug.utils).values()).copy().pop()',
    '{None}.union({"k":werkzeug.utils}.copy().values()).pop()',
    '{werkzeug.utils}.difference({"k":None}.values()).pop()',
    '{werkzeug.utils}.intersection({"k":werkzeug.utils}.values()).pop()',
])
def test_set_method_supported_dictionary_view_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={None}.union({None:werkzeug}.keys()).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union({werkzeug:None}.values()).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union(factory(werkzeug).values()).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union({"k":werkzeug}.values(extra)).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.difference({"k":werkzeug}.values()).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.intersection({"k":werkzeug}.values()).pop()\nsaved.member=value',
    'import werkzeug\nsaved={None}.union({"k":werkzeug}.values())\nsaved.member=value',
])
def test_view_roles_unknown_sources_invalid_shapes_and_fresh_results_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
