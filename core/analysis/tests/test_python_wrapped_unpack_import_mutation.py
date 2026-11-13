"""Single-target unpacking can expose supported iterator members."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_iterator_unpack_cannot_preserve_replaced_callable_identity():
    assert suppression('[saved]=iter((werkzeug.utils,))', 'saved.secure_filename=replacement') is False


def test_copy_unpack_cannot_preserve_replaced_callable_identity():
    assert suppression('(saved,)=list((werkzeug.utils,))', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('binding', [
    '[saved]=iter((werkzeug.utils,))',
    '(saved,)=list((werkzeug.utils,))',
    '[saved]=reversed([werkzeug.utils])',
    '[saved]={werkzeug.utils:None}',
])
def test_single_target_unpack_shared_members_remove_trust(binding):
    assert module_dynamic_namespace(ast.parse('import werkzeug\n'+binding+'\nsaved.member=value')) == (True, frozenset())


def test_single_target_unpack_keeps_namespace_dictionary_kind():
    source='import werkzeug\n[saved]=iter((werkzeug.utils.__dict__,))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\n[saved]=factory(werkzeug)\nsaved.member=value',
    'import werkzeug\n[saved]=holder\nsaved.member=value',
    'import werkzeug\n[saved]={"key":werkzeug}\nsaved.member=value',
    'import werkzeug\n[saved]=iter(([werkzeug.utils],))\nsaved[0]=value',
    'import werkzeug\nother,saved=(werkzeug,None)\nsaved.member=value',
])
def test_unknown_sources_fresh_members_and_exact_literal_pairing_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
