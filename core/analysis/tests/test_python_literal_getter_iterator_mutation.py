"""Known literal member getters can return stored iterator values."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_get_iterator_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next({"chosen":iter((werkzeug.utils,))}.get("chosen"))', 'saved.secure_filename=replacement') is False


def test_getitem_iterator_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"chosen":iter((werkzeug.utils,))}.__getitem__("chosen").__next__()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next({"chosen":iter((werkzeug.utils,))}.get("chosen"))',
    'next([reversed([werkzeug.utils])].__getitem__(0))',
    'next({}.get("missing",iter((werkzeug.utils,))))',
    'next(({"chosen":iter((werkzeug.utils,))} if raw else {}).get("chosen"))',
])
def test_getter_iterator_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_getter_iterator_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=next({"chosen":iter((werkzeug.utils.__dict__,))}.get("chosen"))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(holder.get(werkzeug))\nsaved.member=value',
    'import werkzeug\nsaved=next({werkzeug:holder}.get("chosen"))\nsaved.member=value',
    'import werkzeug\nsaved=next({"chosen":factory(werkzeug)}.get("chosen"))\nsaved.member=value',
    'import werkzeug\nsaved=next({}.get("chosen",iter(([werkzeug.utils],))))\nsaved[0]=value',
])
def test_unknown_origins_keys_and_fresh_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
