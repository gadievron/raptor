"""Literal containers preserve references to stored imported objects."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_literal_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"utils":werkzeug.utils}["utils"]', 'saved.secure_filename=replacement') is False


def test_literal_dictionary_member_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"namespace":werkzeug.utils.__dict__}["namespace"]',
                       'saved.update({"secure_filename":replacement})') is False


@pytest.mark.parametrize('value', [
    '{"utils":werkzeug.utils}["utils"]',
    '[werkzeug.utils][0]',
    '[werkzeug.utils][:][0]',
    '(werkzeug.utils,)[:][0]',
    '[werkzeug.utils][:].__getitem__(0)',
    '(werkzeug.utils,)[0]',
    '{"utils":werkzeug.utils}.get("utils")',
    '[werkzeug.utils].__getitem__(0)',
    '{}.get("utils",werkzeug.utils)',
    '{"namespace":werkzeug.utils.__dict__}.get("namespace")',
])
def test_explicit_literal_member_mutations_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=replacement')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved={"utils":werkzeug.utils}\nsaved["utils"]=value',
    'import werkzeug\nsaved=[werkzeug.utils]\nsaved[0]=value',
    'import werkzeug\nsaved=[werkzeug.utils][:]\nsaved[0]=value',
    'import werkzeug\nsaved=(werkzeug.utils,)[:]\nsaved.member=value',
    'import werkzeug\nsaved={"utils":werkzeug.utils}\nsaved.update(value)',
    'import werkzeug\nsaved={werkzeug:None}[key]\nsaved.member=value',
    'import werkzeug\nsaved=[holder][0]\nsaved.member=value',
])
def test_fresh_container_writes_keys_and_unrelated_values_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
