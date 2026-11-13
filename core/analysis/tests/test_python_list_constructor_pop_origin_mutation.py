"""Explicit list construction preserves iterable member origins for pop results."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_list_constructor_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list((werkzeug.utils,)).pop()', 'saved.secure_filename=replacement') is False


def test_list_constructor_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list([werkzeug.utils]).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'list((werkzeug.utils,)).pop()',
    'list([werkzeug.utils]).copy().pop()',
    'list(iter((werkzeug.utils,))).pop()',
    'list({werkzeug.utils}).pop()',
    'list({werkzeug.utils:None}).pop()',
    'list(list((werkzeug.utils,))).copy().pop()',
    'list((werkzeug.utils,))[:].pop()',
])
def test_list_constructor_supported_iterable_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_builtin_list_alias_preserves_member_namespace_kind():
    source='import werkzeug\nfrom builtins import list as make_list\nsaved=make_list((werkzeug.utils.__dict__,)).copy().pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=list(factory(werkzeug)).pop()\nsaved.member=value',
    'import werkzeug\nsaved=tuple((werkzeug,)).pop()\nsaved.member=value',
    'import werkzeug\nsaved=list((werkzeug,),extra).pop()\nsaved.member=value',
    'import werkzeug\nsaved=list(iterable=(werkzeug,)).pop()\nsaved.member=value',
    'import werkzeug\nsaved=list((werkzeug,))\nsaved[0]=value',
    'import werkzeug\nsaved=list(([werkzeug],)).pop()\nsaved[0]=value',
])
def test_unknown_iterables_invalid_shapes_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
