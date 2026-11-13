"""Reflective member reads can save shared imported mutation receivers."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_getattr_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=getattr(werkzeug,"utils")',
                       'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=getattr(werkzeug,"utils")\nsaved.member=value',
    'import werkzeug\nfrom builtins import getattr as fetch\nsaved=fetch(werkzeug,"utils")\nsaved.member=value',
    'import werkzeug\nsaved=getattr(holder,"field",werkzeug.utils)\nsaved.member=value',
])
def test_known_reflective_result_mutations_remove_trust(source):
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=getattr(werkzeug,"utils")',
    'import werkzeug\nsaved=getattr(holder,"field")\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug,"utils")\nsaved.member=value',
    'import werkzeug\ndef handle():\n    value: getattr(werkzeug,"utils")',
])
def test_reads_unrelated_receivers_arbitrary_calls_and_annotations_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
