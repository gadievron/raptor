"""Named-expression wrappers preserve selected literal container values."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_named_literal_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(holder:=[[werkzeug.utils]])[0][0]',
                       'saved.secure_filename=replacement') is False


def test_named_literal_dictionary_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=(holder:={"inner":{"namespace":werkzeug.utils.__dict__}})["inner"]["namespace"]',
                       'saved.update({"secure_filename":replacement})') is False


@pytest.mark.parametrize('value', [
    '(holder:=[[werkzeug.utils]])[0][0]',
    '(outer:=(inner:=[[werkzeug.utils]]))[0][0]',
    '(holder:={"inner":{"utils":werkzeug.utils}})["inner"].get("utils")',
])
def test_named_literal_selection_members_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=(holder:=[[werkzeug.utils]])[0]\nsaved[0]=value',
    'import werkzeug\nsaved=(holder:={"inner":{"utils":werkzeug.utils}})["inner"]\nsaved.update(value)',
    'import werkzeug\nsaved=(holder:=factory(werkzeug))[0][0]\nsaved.member=value',
    'import werkzeug\nsaved=(holder:=[[other]])[0][0]\nsaved.member=value',
])
def test_named_fresh_container_writes_and_unresolved_sources_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
