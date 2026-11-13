"""Literal set unions copy existing references into a fresh set."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_union_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({werkzeug.utils}|{werkzeug.utils}))', 'saved.secure_filename=replacement') is False


def test_set_union_loop_cannot_preserve_replaced_callable_identity():
    assert suppression('for saved in {werkzeug.utils}|{werkzeug.utils}: saved.secure_filename=replacement', 'pass') is False


@pytest.mark.parametrize('statement', [
    'saved=next(iter({werkzeug.utils}|{werkzeug.utils})); saved.member=value',
    'saved=list({werkzeug.utils}|{None})[0]; saved.member=value',
    'for saved in {None}|{werkzeug.utils}: saved.member=value',
    '[saved.__setattr__("member",value) for saved in {*[werkzeug.utils]}|{None}]',
])
def test_literal_union_iteration_members_remove_trust(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+statement)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter({werkzeug}|holder))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(holder|{werkzeug}))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({"key":werkzeug}|{}))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({(werkzeug,)}|{(werkzeug,)}))\nsaved[0]=value',
    'import werkzeug\nsaved={werkzeug}|{werkzeug}\nsaved.clear()',
])
def test_unknown_operands_mapping_values_and_fresh_set_or_tuple_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
