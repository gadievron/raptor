"""Named expressions preserve exact iterator wrapper values."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_named_next_wrapper_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next((items:=iter((werkzeug.utils,))))', 'saved.secure_filename=replacement') is False


def test_named_bound_wrapper_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(items:=iter((werkzeug.utils,))).__next__()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next((items:=iter((werkzeug.utils,))))',
    '(items:=reversed([werkzeug.utils])).__next__()',
    'next((outer:=(inner:=iter((werkzeug.utils,)))))',
])
def test_named_wrapper_member_values_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next((items:=factory(werkzeug)))\nsaved.member=value',
    'import werkzeug\nsaved=(items:=holder).__next__()\nsaved.member=value',
    'import werkzeug\nsaved=next((items:=iter(())),[werkzeug.utils])\nsaved[0]=value',
])
def test_unknown_named_iterators_and_fresh_defaults_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
