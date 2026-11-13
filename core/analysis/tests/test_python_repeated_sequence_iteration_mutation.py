"""Supported literal repetition iteration exposes members."""

import ast
import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_repeated_next_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter([werkzeug.utils]*2))', 'saved.secure_filename=replacement') is False


def test_repeated_loop_cannot_preserve_replaced_callable_identity():
    assert suppression('for saved in 2*[werkzeug.utils]: saved.secure_filename=replacement', 'pass') is False


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter([werkzeug]*count))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter([werkzeug]*0))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter([werkzeug]*-1))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter([[werkzeug]]*2))\nsaved[0]=value',
])
def test_unknown_nonpositive_counts_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


@pytest.mark.parametrize('value', [
    'next(iter(2*(werkzeug.utils,)))',
    'list([werkzeug.utils]*2)[0]',
    'next(iter([werkzeug.utils]*1000000000000000000))',
])
def test_positive_literal_repeat_iteration_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_repeated_sequence_iteration_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=next(iter([werkzeug.utils.__dict__]*2))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())
