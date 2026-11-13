"""Empty dictionary merges preserve shared namespace member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_merged_namespace_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(werkzeug.__dict__ | {})["utils"]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '(werkzeug.__dict__ | {})["utils"]',
    '({} | werkzeug.__dict__)["utils"]',
    '(werkzeug.__dict__ | {}).get("utils")',
])
def test_empty_merge_members_remove_trust_on_mutation(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=werkzeug.__dict__ | {}\nsaved["member"]=value',
    'import werkzeug\nsaved=werkzeug.__dict__ | {}\nsaved.update(value)',
    'import werkzeug\nsaved=(holder.__dict__ | {})["member"]\nsaved.member=value',
])
def test_fresh_merged_mappings_and_unresolved_objects_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
