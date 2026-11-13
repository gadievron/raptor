"""Named expression mapping values preserve supported view origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_named_copied_values_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter((items:={"chosen":werkzeug.utils}.copy()).values()))', 'saved.secure_filename=replacement') is False


def test_named_copied_keys_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter((items:={werkzeug.utils:None}.copy()).keys()))', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter((items:={"chosen":werkzeug.utils}.copy()).values()))',
    'next(iter((items:=dict(chosen=werkzeug.utils)).values()))',
    'next(iter((outer:=(inner:={werkzeug.utils:None}.copy())).copy().keys()))',
])
def test_named_mapping_view_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_named_copied_values_keep_namespace_dictionary_kind():
    source='import werkzeug\nsaved=next(iter((items:={"chosen":werkzeug.utils.__dict__}.copy()).values()))\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter((items:=holder.copy()).values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter((items:=factory(werkzeug)).values()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter((items:={"key":werkzeug}.copy()).keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter((items:={"key":[werkzeug]}.copy()).values()))\nsaved[0]=value',
    'import werkzeug\nsaved=(items:={"key":werkzeug}.copy())\nsaved["key"]=value',
])
def test_unknown_origins_key_roles_and_fresh_mappings_or_members_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
