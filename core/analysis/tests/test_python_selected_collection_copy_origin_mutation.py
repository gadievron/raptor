"""Guarded literal member selection preserves known collection origins."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_selected_list_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[[werkzeug.utils]][0].copy().pop()', 'saved.secure_filename=replacement') is False


def test_selected_set_copy_pop_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=[{werkzeug.utils}][0].copy().pop()', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '[[werkzeug.utils]][0].copy().pop()',
    '[{werkzeug.utils}][0].copy().pop()',
    '{"chosen":[werkzeug.utils]}["chosen"].copy().pop()',
    '[None,[werkzeug.utils]][-1].copy().pop()',
    '[[[werkzeug.utils]]][0][0].copy().pop()',
])
def test_supported_literal_lookup_collection_origins_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_selected_list_copy_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved=[[werkzeug.utils.__dict__]][0].copy().pop()\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=[[werkzeug]][index].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug)[0].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]][1].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[[werkzeug]]][0].copy().pop()\nsaved[0]=value',
    'import werkzeug\nsaved=[(werkzeug,)][0].copy().pop()\nsaved.member=value',
    'import werkzeug\nsaved=[[werkzeug]][0].copy()\nsaved[0]=value',
])
def test_unknown_lookup_origins_other_kinds_and_fresh_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
