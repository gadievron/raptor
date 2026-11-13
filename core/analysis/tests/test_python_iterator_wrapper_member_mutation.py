"""Known iterator wrappers preserve explicit member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_iter_wrapper_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(iter((werkzeug.utils,)))[0]', 'saved.secure_filename=replacement') is False


def test_reversed_wrapper_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=tuple(reversed([werkzeug.utils]))[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list(iter((werkzeug.utils,)))[0]',
    'tuple(reversed([werkzeug.utils]))[0]',
    'list(iter({"utils":werkzeug.utils}.values()))[0]',
    'list(reversed({werkzeug.utils:None}))[0]',
])
def test_supported_iterator_wrappers_expose_member_references(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_absolute_builtin_iterator_alias_retains_member_reference():
    source='import werkzeug\nfrom builtins import iter as items\nsaved=list(items((werkzeug.utils,)))[0]\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list(iter((werkzeug.utils,)))\nsaved[0]=value',
    'import werkzeug\nsaved=list(iter(factory(werkzeug)))[0]\nsaved.member=value',
    'import werkzeug\nsaved=list(iter(factory,werkzeug))[0]\nsaved.member=value',
    'import werkzeug\nsaved=list(reversed(holder))[0]\nsaved.member=value',
])
def test_fresh_results_callable_sentinel_and_unknown_origins_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
