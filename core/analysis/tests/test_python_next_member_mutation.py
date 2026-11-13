"""Explicit iterator advancement can return shared imported objects."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_next_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter((werkzeug.utils,)))', 'saved.secure_filename=replacement') is False


def test_next_dictionary_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter((werkzeug.utils.__dict__,)))',
                       'saved.update({"secure_filename":replacement})') is False


def test_next_default_cannot_preserve_replaced_callable_identity():
    assert suppression('holder=iter(())\n    saved=next(holder,werkzeug.utils)',
                       'saved.secure_filename=replacement') is False


def test_bound_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=iter((werkzeug.utils,)).__next__()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter((werkzeug.utils,)))',
    'next(reversed([werkzeug.utils]))',
    'next(iter(()),werkzeug.utils)',
    'iter((werkzeug.utils,)).__next__()',
])
def test_explicit_advancement_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_absolute_builtin_next_alias_retains_member_reference():
    source='import werkzeug\nfrom builtins import next as advance\nsaved=advance(iter((werkzeug.utils,)))\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter(()),[werkzeug.utils])\nsaved[0]=value',
    'import werkzeug\nsaved=next(holder)\nsaved.member=value',
    'import werkzeug\nsaved=next(factory(werkzeug))\nsaved.member=value',
    'import werkzeug\nsaved=holder.__next__()\nsaved.member=value',
])
def test_fresh_default_containers_and_unknown_iterator_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
