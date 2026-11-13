"""Dictionary constructor keys views retain positional key references."""

import ast

import pytest

from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.tests.test_python_reflective_callable_escape import suppression


def test_mapping_constructor_keys_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=next(iter(dict({werkzeug.utils:None}).keys()))', 'saved.secure_filename=replacement') is False


def test_pair_constructor_keys_cannot_preserve_replaced_callable_identity():
    assert suppression('saved=list(dict([(werkzeug.utils,None)]).keys())[0]', 'saved.secure_filename=replacement') is False


@pytest.mark.parametrize('value', [
    'next(iter(dict({werkzeug.utils:None}).keys()))',
    'list(dict([(werkzeug.utils,None)]).keys())[0]',
    'next(iter(dict({werkzeug.utils:None},other=None).copy().keys()))',
])
def test_constructor_positional_keys_remove_trust(value):
    assert module_dynamic_namespace(ast.parse('import werkzeug\nsaved='+value+'\nsaved.member=value')) == (True, frozenset())


@pytest.mark.parametrize('source', [
    'import werkzeug\nsaved=next(iter(dict({"key":werkzeug}).keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict([("key",werkzeug)]).keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict(chosen=werkzeug).keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict(**{"chosen":werkzeug}).keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict(holder).keys()))\nsaved.member=value',
    'import werkzeug\nsaved=next(iter(dict({(werkzeug,):None}).keys()))\nsaved[0]=value',
])
def test_values_keyword_inputs_unknown_sources_and_fresh_keys_keep_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
