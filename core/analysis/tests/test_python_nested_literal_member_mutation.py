"""Nested literal selections retain shared member object references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_nested_literal_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[[werkzeug.utils]][0][0]', 'saved.secure_filename=replacement') is False


def test_nested_literal_dictionary_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"inner":{"namespace":werkzeug.utils.__dict__}}["inner"]["namespace"]',
                       'saved.update({"secure_filename":replacement})') is False


@pytest.mark.parametrize('value', [
    '[[werkzeug.utils]][0][0]',
    '[[werkzeug.utils]][-1][-1]',
    '[[[werkzeug.utils]]][0][0][0]',
    '{"inner":{"utils":werkzeug.utils}}["inner"]["utils"]',
    '{"inner":{"utils":werkzeug.utils}}["inner"].get("utils")',
    '[{"utils":werkzeug.utils}][0]["utils"]',
])
def test_literal_selected_containers_expose_shared_members(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=[[werkzeug.utils]][0]\nsaved[0]=value',
    'import werkzeug\nsaved={"inner":{"utils":werkzeug.utils}}["inner"]\nsaved["utils"]=value',
    'import werkzeug\nsaved=[[holder]][0][0]\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug)[0][0]\nsaved.member=value',
    'import werkzeug\nsaved={"inner":{werkzeug:None}}["inner"][key]\nsaved.member=value',
])
def test_selected_fresh_containers_keys_and_opaque_sources_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_selected_container_preserves_existing_namespace_dictionary_possibility():
    binding=('holder={"namespace":werkzeug.utils.__dict__}\n'
             '    saved=({"chosen":holder,"other":werkzeug.utils.__dict__}["chosen"] if raw else {}).get("namespace")')
    assert suppression(binding, 'saved.update({"secure_filename":replacement})') is False
