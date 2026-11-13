"""Object namespace lookups can save shared imported mutation receivers."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_vars_import_value_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=vars(werkzeug)["utils"]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=vars(werkzeug)["utils"]\nsaved.member=value',
    'import werkzeug\nfrom builtins import vars as namespace\nsaved=namespace(werkzeug)["utils"]\nsaved.member=value',
])
def test_object_namespace_result_mutations_remove_trust(source):
    assert module_dynamic_namespace(ast.parse(source)) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=vars(werkzeug)["utils"]',
    'import werkzeug\nsaved=vars(holder)["member"]\nsaved.member=value',
    'import werkzeug\nsaved=factory(werkzeug)["member"]\nsaved.member=value',
])
def test_reads_unrelated_namespaces_and_arbitrary_calls_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
