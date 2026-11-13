"""Shallow literal set copies retain references in popped members."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_set_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={werkzeug.utils}.copy().pop()', 'saved.secure_filename=replacement') is False


def test_copied_expanded_set_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={*[werkzeug.utils]}.copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{werkzeug.utils}.copy().pop()',
    '{*[werkzeug.utils]}.copy().pop()',
    '(items:={werkzeug.utils}.copy()).pop()',
])
def test_literal_set_copy_pop_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=holder.copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={*factory(werkzeug)}.copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved={(werkzeug,)}.copy().pop()\nsaved[0]=value',
    'import werkzeug\nsaved={werkzeug}.copy()\nsaved.clear()',
    'import werkzeug\nsaved={werkzeug}.copy({}).pop()\nsaved.member=value',
])
def test_unknown_sources_fresh_copies_or_members_and_invalid_copy_shapes_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
