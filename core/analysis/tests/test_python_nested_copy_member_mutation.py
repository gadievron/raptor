"""Repeated shallow namespace copies preserve shared member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_nested_constructor_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict(dict(werkzeug.__dict__))["utils"]',
                       'saved.secure_filename=replacement') is False


def test_nested_copy_method_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=werkzeug.__dict__.copy().copy()["utils"]',
                       'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'dict(dict(werkzeug.__dict__))["utils"]',
    'werkzeug.__dict__.copy().copy()["utils"]',
    'dict(werkzeug.__dict__.copy()).get("utils")',
    '(dict(werkzeug.__dict__) | {})["utils"]',
    'dict(werkzeug.__dict__ | {})["utils"]',
    '(werkzeug.__dict__ | {}).copy()["utils"]',
])
def test_mixed_copy_chain_members_remove_trust_on_mutation(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=dict(dict(werkzeug.__dict__))\nsaved["member"]=value',
    'import werkzeug\nsaved=werkzeug.__dict__.copy().copy()\nsaved.update(value)',
    'import werkzeug\nsaved=dict(factory(werkzeug.__dict__))["member"]\nsaved.member=value',
    'import werkzeug\nsaved=factory(dict(werkzeug.__dict__))["member"]\nsaved.member=value',
])
def test_copy_container_writes_and_unresolved_chain_links_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
