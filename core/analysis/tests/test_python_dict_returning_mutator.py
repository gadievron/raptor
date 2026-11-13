"""Dictionary mutation results can retain shared member references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_setdefault_result_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"chosen":werkzeug.utils}.setdefault("chosen")', 'saved.secure_filename=replacement') is False


def test_pop_result_cannot_preserve_replaced_callable_identity():
    assert suppression('saved={"chosen":werkzeug.utils}.pop("chosen")', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    '{"chosen":werkzeug.utils}.setdefault("chosen")',
    '{"chosen":werkzeug.utils}.pop("chosen")',
    '{}.setdefault("chosen",werkzeug.utils)',
    '{}.pop("chosen",werkzeug.utils)',
    'dict(chosen=werkzeug.utils).pop("chosen")',
])
def test_dictionary_member_or_default_results_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


def test_dictionary_mutation_result_keeps_namespace_dictionary_kind():
    source='import werkzeug\nsaved={"chosen":werkzeug.utils.__dict__}.pop("chosen")\nsaved.update({})'
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=holder.pop("chosen",werkzeug)\nsaved.member=value',
    'import werkzeug\nsaved=holder.setdefault("chosen",werkzeug)\nsaved.member=value',
    'import werkzeug\nsaved={werkzeug:holder}.pop("chosen")\nsaved.member=value',
    'import werkzeug\nsaved={}.setdefault("chosen",[werkzeug])\nsaved[0]=value',
    'import werkzeug\nsaved={"chosen":[werkzeug]}.pop("chosen")\nsaved[0]=value',
])
def test_unknown_methods_keys_and_fresh_returned_containers_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
