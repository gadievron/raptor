"""Dictionary constructors retain explicit pair values, not pair keys."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_pair_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict([("utils",werkzeug.utils)])["utils"]',
                       'saved.secure_filename=replacement') is False


def test_pair_dictionary_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=dict([("namespace",werkzeug.utils.__dict__)])["namespace"]',
                       'saved.update({"secure_filename":replacement})') is False


@pytest.mark.parametrize('value', [
    'dict([("utils",werkzeug.utils)])["utils"]',
    'dict((("utils",werkzeug.utils),))["utils"]',
    'dict([["utils",werkzeug.utils]]).get("utils")',
    'dict([*( ("utils",werkzeug.utils), )])["utils"]',
])
def test_explicit_pair_values_remove_trust_on_member_mutation(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=dict([("utils",werkzeug.utils)])\nsaved["utils"]=value',
    'import werkzeug\nsaved=dict([("utils",werkzeug.utils)])\nsaved.update(value)',
    'import werkzeug\nsaved=dict([(werkzeug,None)])[key]\nsaved.member=value',
    'import werkzeug\nsaved=dict([("utils",[werkzeug.utils])])["utils"]\nsaved[0]=value',
    'import werkzeug\nsaved=dict(factory(werkzeug))["utils"]\nsaved.member=value',
])
def test_pair_keys_fresh_containers_and_unresolved_inputs_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
