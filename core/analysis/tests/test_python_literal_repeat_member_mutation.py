"""Positive literal sequence repetition preserves shared element references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_list_repeat_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=([werkzeug.utils]*2)[0]', 'saved.secure_filename=replacement') is False


def test_tuple_repeat_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(2*(werkzeug.utils,))[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '([werkzeug.utils]*2)[0]',
    '(2*[werkzeug.utils])[0]',
    '((werkzeug.utils,)*2)[0]',
    '([werkzeug.utils]*1000000000000000000)[0]',
])
def test_positive_literal_repetition_members_remove_trust_without_expansion(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_literal_repetition_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=([werkzeug.utils.__dict__]*2)[0]\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=([werkzeug]*count)[0]\nsaved.member=value',
    'import werkzeug\nsaved=(holder*2)[0]\nsaved.member=value',
    'import werkzeug\nsaved=([werkzeug]*0)[0]\nsaved.member=value',
    'import werkzeug\nsaved=([werkzeug]*-1)[0]\nsaved.member=value',
    'import werkzeug\nsaved=[werkzeug]*2\nsaved[0]=value',
    'import werkzeug\nsaved=([[werkzeug]]*2)[0]\nsaved[0]=value',
])
def test_unknown_nonpositive_counts_and_fresh_sequences_or_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
