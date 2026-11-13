"""Exact literal sequence getitem retains selected collection origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_sequence_getitem_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[[werkzeug.utils]].__getitem__(0).copy().pop()', 'saved.secure_filename=replacement') is False


def test_sequence_getitem_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[{werkzeug.utils}].__getitem__(0).copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[[werkzeug.utils]].__getitem__(0).copy().pop()',
    '[{werkzeug.utils}].__getitem__(0).copy().pop()',
    '(None,[werkzeug.utils]).__getitem__(-1).copy().pop()',
    '[[[werkzeug.utils]]][0].__getitem__(0).copy().pop()',
])
def test_exact_sequence_getitem_selected_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_sequence_getitem_retains_existing_iteration_uncertainty():
    source='import werkzeug\nfor saved in [[None],[werkzeug]].__getitem__(0):\n    saved.member=value'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=[[werkzeug]].__getitem__(index).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].__getitem__(1).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].__getitem__(True).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[*[werkzeug]].__getitem__(0).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[(werkzeug,)].__getitem__(0).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].__getitem__(0,extra).copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]].__getitem__(0).copy()\nsaved[0]=value',
])
def test_unknown_indices_invalid_shapes_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
