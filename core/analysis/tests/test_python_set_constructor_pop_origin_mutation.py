"""Set constructors preserve iterable member origins through pop results."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_set_constructor_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=set((werkzeug.utils,)).pop()', 'saved.secure_filename=replacement') is False


def test_set_constructor_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=set((werkzeug.utils,)).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'set((werkzeug.utils,)).pop()',
    'set([werkzeug.utils]).copy().pop()',
    'set(iter((werkzeug.utils,))).pop()',
    'set({werkzeug.utils}).pop()',
    'set({werkzeug.utils:None}).pop()',
    'set(set((werkzeug.utils,))).copy().pop()',
    '(set((werkzeug.utils,)) if flag else set(())).copy().pop()',
])
def test_set_constructor_supported_iterable_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_builtin_set_alias_preserves_imported_member_origin():
    source='import werkzeug\nfrom builtins import set as make_set\nsaved=make_set((werkzeug.utils,)).copy().pop()\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


def test_set_constructor_iteration_keeps_member_origin():
    source='import werkzeug\nfor saved in set((werkzeug.utils,)):\n    saved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=set(factory(werkzeug)).pop()\nsaved.member=value',
    'import werkzeug\nsaved=frozenset((werkzeug,)).pop()\nsaved.member=value',
    'import werkzeug\nsaved=set((werkzeug,),extra).pop()\nsaved.member=value',
    'import werkzeug\nsaved=set(iterable=(werkzeug,)).pop()\nsaved.member=value',
    'import werkzeug\nsaved=set((werkzeug,))\nsaved.member=value',
])
def test_unknown_iterables_invalid_shapes_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
