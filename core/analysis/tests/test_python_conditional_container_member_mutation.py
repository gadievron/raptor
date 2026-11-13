"""Conditional container results preserve shared object member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_conditional_copy_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(werkzeug.__dict__.copy() if raw else werkzeug.__dict__.copy())["utils"]',
                       'saved.secure_filename=replacement') is False


def test_copy_of_conditional_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict(werkzeug.__dict__.copy() if raw else werkzeug.__dict__.copy())["utils"]',
                       'saved.secure_filename=replacement') is False


def test_constructor_literal_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict({"utils":werkzeug.utils})["utils"]',
                       'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '(werkzeug.__dict__.copy() if condition else werkzeug.__dict__.copy())["utils"]',
    '(werkzeug.__dict__.copy() or werkzeug.__dict__.copy()).get("utils")',
    'dict({"utils":werkzeug.utils})["utils"]',
    '({"utils":werkzeug.utils} if condition else {}).get("utils")',
    '(werkzeug.__dict__ if condition else holder.__dict__.copy())["utils"]',
])
def test_known_container_result_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=(werkzeug.__dict__.copy() if condition else werkzeug.__dict__.copy())\nsaved["utils"]=value',
    'import werkzeug\nsaved=dict({"utils":werkzeug.utils})\nsaved.update(value)',
    'import werkzeug\nsaved=werkzeug.copy()["member"]\nsaved.member=value',
    'import werkzeug\nsaved=dict(factory(werkzeug.__dict__))["member"]\nsaved.member=value',
    'import werkzeug\nsaved=(first if werkzeug.__dict__ else second)["member"]\nsaved.member=value',
])
def test_fresh_container_writes_conditions_and_unknown_copy_origins_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_partial_projection_keeps_existing_copied_namespace_source():
    assert suppression('saved=dict(({"ns":werkzeug.__dict__}["ns"]) if raw else {})["utils"]',
                       'saved.secure_filename=replacement') is False


def test_partial_getter_projection_keeps_existing_copied_namespace_source():
    assert suppression('saved=dict(({"ns":werkzeug.__dict__}["ns"]) if raw else {}).get("utils")',
                       'saved.secure_filename=replacement') is False
