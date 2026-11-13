"""Expanded literal members preserve shared imported object references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_mapping_expansion_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={**werkzeug.__dict__}["utils"]', 'saved.secure_filename=replacement') is False


def test_sequence_expansion_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[*(werkzeug.utils,)][0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{**werkzeug.__dict__}["utils"]',
    '{**{"utils":werkzeug.utils}}["utils"]',
    '{**{**{"utils":werkzeug.utils}}}.get("utils")',
    '[*(werkzeug.utils,)][0]',
    '(*[werkzeug.utils],)[0]',
    '[*[*(werkzeug.utils,)]][0]',
])
def test_expanded_literal_member_mutations_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={**werkzeug.__dict__}\nsaved["member"]=value',
    'import werkzeug\nsaved=[*(werkzeug.utils,)]\nsaved[0]=value',
    'import werkzeug\nsaved={**{werkzeug:None}}[key]\nsaved.member=value',
    'import werkzeug\nsaved=[*(holder,)][0]\nsaved.member=value',
])
def test_expanded_fresh_container_writes_keys_and_unrelated_values_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
