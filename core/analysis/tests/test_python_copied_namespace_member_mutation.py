"""Shallow namespace copies preserve member object aliases."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_namespace_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=werkzeug.__dict__.copy()["utils"]',
                       'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'werkzeug.__dict__.copy()["utils"]',
    'werkzeug.__dict__.copy().get("utils")',
    'werkzeug.__dict__.copy().__getitem__("utils")',
    'vars(werkzeug).copy()["utils"]',
])
def test_copied_namespace_members_remove_trust_on_mutation(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=replacement')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=werkzeug.__dict__.copy()',
    'import werkzeug\nsaved=werkzeug.__dict__.copy()\nsaved["member"]=value',
    'import werkzeug\nsaved=werkzeug.__dict__.copy()\nsaved.update(value)',
    'import werkzeug\nsaved=holder.__dict__.copy()["member"]\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug).copy()["member"]\nsaved.member=value',
])
def test_fresh_mapping_writes_and_unresolved_copies_preserve_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
