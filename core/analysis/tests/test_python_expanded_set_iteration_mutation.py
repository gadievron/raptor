"""Starred set elements retain supported source member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_expanded_set_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({*[werkzeug.utils]}))', 'saved.secure_filename=replacement') is False


def test_expanded_set_loop_cannot_preserve_replaced_callable_identity():
    assert suppression('for saved in {*[werkzeug.utils]}: saved.secure_filename=replacement', 'pass') is False


@pytest.mark.parametrize('value', [
    'next(iter({*[werkzeug.utils]}))',
    'list({*iter((werkzeug.utils,))})[0]',
    'next(iter({*{werkzeug.utils:None}}))',
    'next(iter({*{*{werkzeug.utils}}}))',
    'next(iter({None,*[werkzeug.utils]}))',
])
def test_supported_set_expansion_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter({*factory(werkzeug)}))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({*holder}))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({*{"key":werkzeug}}))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({*[(werkzeug,)]}))\nsaved[0]=value',
    'import werkzeug\nsaved={*[werkzeug]}\nsaved.clear()',
])
def test_unknown_expansions_mapping_values_and_fresh_set_or_tuple_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
