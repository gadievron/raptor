"""Expanding copied mappings preserves shared member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_expanded_constructor_copy_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={**dict(werkzeug.__dict__)}["utils"]', 'saved.secure_filename=replacement') is False


def test_expanded_method_copy_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={**werkzeug.__dict__.copy()}["utils"]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{**dict(werkzeug.__dict__)}["utils"]',
    '{**werkzeug.__dict__.copy()}["utils"]',
    '{**(werkzeug.__dict__.copy() if condition else werkzeug.__dict__.copy())}.get("utils")',
    '{**{**dict(werkzeug.__dict__)}}["utils"]',
])
def test_expanded_copy_members_remove_trust_on_mutation(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={**dict(werkzeug.__dict__)}\nsaved["member"]=value',
    'import werkzeug\nsaved={**werkzeug.__dict__.copy()}\nsaved.update(value)',
    'import werkzeug\nsaved={**factory(werkzeug.__dict__)}["member"]\nsaved.member=value',
    'import werkzeug\nsaved={**dict({werkzeug:None})}[key]\nsaved.member=value',
])
def test_fresh_expanded_mapping_writes_keys_and_opaque_calls_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
