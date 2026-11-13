"""Iterator result branches retain shared namespace member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_conditional_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter((werkzeug.utils,)) if raw else iter((werkzeug.utils,)))', 'saved.secure_filename=replacement') is False


def test_conditional_bound_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(iter((werkzeug.utils,)) if raw else iter((werkzeug.utils,))).__next__()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter((werkzeug.utils,)) if raw else holder)',
    'next(holder or reversed([werkzeug.utils]))',
    '(iter((werkzeug.utils,)) and holder).__next__()',
    'next((items:=(iter((werkzeug.utils,)) if raw else holder)))',
])
def test_supported_iterator_result_branches_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_conditional_namespace_dictionary_members_keep_dictionary_kind():
    source = 'import werkzeug\nsaved=next(iter((werkzeug.utils.__dict__,)) if raw else holder)\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(holder if werkzeug else other)\nsaved.member=value',
    'import werkzeug\nsaved=next(factory(werkzeug) or holder)\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(()) if raw else iter(()),[werkzeug.utils])\nsaved[0]=value',
    'import werkzeug\nsaved=next(iter(([werkzeug.utils],)) if raw else holder)\nsaved[0]=value',
])
def test_unknown_origins_conditions_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
