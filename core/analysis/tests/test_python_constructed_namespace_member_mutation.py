"""Dictionary constructor copies preserve shared namespace member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_constructed_namespace_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict(werkzeug.__dict__)["utils"]', 'saved.secure_filename=replacement') is False


def test_expanded_namespace_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict(**werkzeug.__dict__)["utils"]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'dict(werkzeug.__dict__)["utils"]',
    'dict(**werkzeug.__dict__)["utils"]',
    'dict(werkzeug.__dict__).get("utils")',
    'dict(vars(werkzeug))["utils"]',
])
def test_constructed_namespace_members_remove_trust_on_mutation(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=replacement')) == (True, frozenset())


def test_absolute_builtin_dict_alias_preserves_shared_members():
    source='import werkzeug\nfrom builtins import dict as mapping\nsaved=mapping(werkzeug.__dict__)["utils"]\nsaved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=dict(werkzeug.__dict__)\nsaved["member"]=value',
    'import werkzeug\nsaved=dict(**werkzeug.__dict__)\nsaved.update(value)',
    'import werkzeug\nsaved=dict(holder.__dict__)["member"]\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug.__dict__)["member"]\nsaved.member=value',
])
def test_fresh_constructed_mappings_and_unresolved_calls_preserve_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
