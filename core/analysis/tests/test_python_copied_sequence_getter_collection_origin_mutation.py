"""Shallow sequence copies preserve exact getter collection result origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_copied_sequence_pop_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[[werkzeug.utils]].copy().pop().copy().pop()', 'saved.secure_filename=replacement') is False


def test_copied_sequence_getitem_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[{werkzeug.utils}].copy().__getitem__(0).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[[werkzeug.utils]].copy().pop().copy().pop()',
    '[{werkzeug.utils}].copy().__getitem__(0).copy().pop()',
    '[[werkzeug.utils]].copy().copy().pop(0).copy().pop()',
    '[None,[werkzeug.utils]].copy().__getitem__(-1).copy().pop()',
    '[[[werkzeug.utils]]][0].copy().pop().copy().pop()',
])
def test_copied_sequence_exact_getter_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=factory(werkzeug).copy().pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].copy(extra).pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].copy().__getitem__(index).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].copy().pop(1).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[(werkzeug,)].copy().pop().copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].copy().pop().copy()\nsaved[0]=value',
])
def test_unknown_copies_invalid_shapes_selection_roles_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
