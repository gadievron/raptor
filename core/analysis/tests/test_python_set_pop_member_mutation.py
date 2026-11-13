"""Literal set pop returns existing element references without ordering proof."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={werkzeug.utils}.pop()', 'saved.secure_filename=replacement') is False


def test_expanded_set_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={*[werkzeug.utils]}.pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{werkzeug.utils}.pop()',
    '{*[werkzeug.utils]}.pop()',
    '{None,werkzeug.utils}.pop()',
    '{*iter((werkzeug.utils,))}.pop()',
])
def test_literal_set_pop_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=holder.pop()\nsaved.member=value',
    'import werkzeug\nsaved={*factory(werkzeug)}.pop()\nsaved.member=value',
    'import werkzeug\nsaved={(werkzeug,)}.pop()\nsaved[0]=value',
    'import werkzeug\nsaved={werkzeug}.pop(0)\nsaved.member=value',
    'import werkzeug\nsaved={werkzeug}.pop(index=0)\nsaved.member=value',
    'import werkzeug\nsaved={werkzeug}\nsaved.clear()',
])
def test_unknown_sources_fresh_members_and_invalid_pop_shapes_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
