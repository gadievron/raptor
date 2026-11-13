"""Literal list pop retains selected collection result origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_list_pop_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[[werkzeug.utils]].pop().copy().pop()', 'saved.secure_filename=replacement') is False


def test_list_pop_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[{werkzeug.utils}].pop(0).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[[werkzeug.utils]].pop().copy().pop()',
    '[{werkzeug.utils}].pop(0).copy().pop()',
    '[None,[werkzeug.utils]].pop(-1).copy().pop()',
    '[[[werkzeug.utils]]][0].pop().copy().pop()',
])
def test_literal_list_pop_selected_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=[[werkzeug]].pop(index).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].pop(1).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].pop(True).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[*[[werkzeug]]].pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[(werkzeug,)].pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=([werkzeug],).pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].pop(0,extra).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].pop().copy()\nsaved[0]=value',
])
def test_unknown_indices_invalid_shapes_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
