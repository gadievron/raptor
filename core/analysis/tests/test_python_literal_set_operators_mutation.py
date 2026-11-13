"""Literal set operator results retain possible operand element references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_difference_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({werkzeug.utils}-{None}))', 'saved.secure_filename=replacement') is False


def test_set_intersection_cannot_preserve_replaced_callable_identity():
    assert suppression('for saved in {werkzeug.utils}&{werkzeug.utils}: saved.secure_filename=replacement', 'pass') is False


def test_set_symmetric_difference_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter({werkzeug.utils}^{*[]}))', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter({werkzeug.utils}-{None}))',
    'list({werkzeug.utils}&{werkzeug.utils})[0]',
    'next(iter({werkzeug.utils}^{*[]}))',
    'next(iter({*[]}^{werkzeug.utils}))',
])
def test_literal_set_operator_iteration_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter({None}-{werkzeug}))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({None}&{werkzeug}))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({werkzeug}-holder))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(holder^{werkzeug}))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter({(werkzeug,)}-{None}))\nsaved[0]=value',
    'import werkzeug\nsaved={werkzeug}-{None}\nsaved.clear()',
])
def test_right_only_subset_sources_unknown_operands_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
