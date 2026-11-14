"""Owned CPython witnesses for separate generic function identity scopes."""
import ast

import pytest

from core.analysis.python_module_callgraph import (
    function_scope_bindings, local_binding_names, module_distrusted_roots,
)
from core.dataflow.source_identity import known_python_identity_conflict


SOURCE = ("html = 'owned-module-root'\n"
          "seen = []\n"
          "def capture(value):\n"
          "    seen.append(value)\n"
          "    return lambda fn: fn\n"
          "@capture(html)\n"
          "def helper[html](value=html):\n"
          "    return html\n")


def test_generic_function_body_identity_includes_type_parameter():
    namespace = {'__name__': 'owned_generic_scope_fixture'}
    exec(compile(SOURCE, '<owned-generic-scope>', 'exec', dont_inherit=True), namespace)
    helper = namespace['helper']
    parameter = helper.__type_params__[0]
    assert helper() is parameter
    assert helper.__defaults__[0] == 'owned-module-root'
    assert namespace['seen'] == ['owned-module-root']
    assert namespace['html'] == 'owned-module-root'
    tree = ast.parse(SOURCE)
    function = tree.body[-1]
    assert isinstance(function, ast.FunctionDef)
    assert 'html' not in local_binding_names(function)
    assert 'html' in function_scope_bindings(tree)[function]



@pytest.mark.parametrize('definition,expected', [
    ('def helper[html]():\n    def nested():\n        return html\n    return nested()\n',
     'parameter'),
    ('def helper[html]():\n    global html\n    return html\n', 'module'),
    ('def helper[html]():\n    global html\n    def nested():\n        return html\n    return nested()\n',
     'module'),
    ('def helper[html]():\n    def nested():\n        global html\n        return html\n    return nested()\n',
     'module'),
    ('def helper[html]():\n    def nested[html](value=html):\n        return value\n    return nested()\n',
     'parameter'),
], ids=['closure', 'generic-global', 'generic-global-nested', 'nested-global', 'nested-generic-default'])
def test_generic_runtime_lookup_contract(definition, expected):
    namespace = {'__name__': 'owned_generic_nested_fixture'}
    source = "html = 'owned-module-root'\n" + definition
    exec(compile(source, '<owned-generic-nested-scope>', 'exec', dont_inherit=True), namespace)
    helper = namespace['helper']
    if expected == 'parameter':
        assert helper() is helper.__type_params__[0]
    else:
        assert helper() == 'owned-module-root'
    tree = ast.parse(source)
    scopes = function_scope_bindings(tree)
    function = tree.body[-1]
    assert ('html' in scopes[function]) is ('global html' not in definition.split('def nested')[0])
    nested = next((node for node in function.body if isinstance(node, ast.FunctionDef)), None)
    if nested is not None:
        assert ('html' in scopes[nested]) is ('global html' not in definition)


def test_type_parameter_nonlocal_binding_is_rejected_by_cpython():
    source = ('def helper[html]():\n'
              '    def nested():\n        nonlocal html\n        return html\n')
    with pytest.raises(SyntaxError, match='nonlocal binding not allowed for type parameter'):
        compile(source, '<owned-generic-nonlocal>', 'exec', dont_inherit=True)


@pytest.mark.parametrize('parameters', ['html', '*html', '**html'],
                         ids=['typevar', 'typevartuple', 'paramspec'])
@pytest.mark.parametrize('prefix', ['def', 'async def'], ids=['function', 'async-function'])
def test_generic_body_identity_refusal_keeps_ordinary_bindings_separate(parameters, prefix):
    source = 'import html\n' + prefix + ' helper[' + parameters + '](value):\n    return html.escape(value)\n'
    tree = ast.parse(source)
    function = tree.body[-1]
    assert 'html' in function_scope_bindings(tree)[function]
    assert 'html' not in local_binding_names(function)
    assert 'html' not in module_distrusted_roots(tree)
    assert known_python_identity_conflict(source, 3, ('html.escape',)) == 'source library root is locally shadowed'


def test_generic_defaults_and_decorators_keep_defining_scope():
    source = ('@((lambda: html)())\n'
              'def helper[html](value=(lambda: html)):\n    return html\n')
    tree = ast.parse(source)
    function = tree.body[0]
    scopes = function_scope_bindings(tree)
    lambdas = [node for node in ast.walk(function) if isinstance(node, ast.Lambda)]
    assert len(lambdas) == 2
    assert all('html' not in scopes[node] for node in lambdas)
    assert 'html' in scopes[function]


def test_ordinary_function_identity_scope_keeps_existing_precision():
    source = 'import html\ndef helper(value):\n    return html.escape(value)\n'
    tree = ast.parse(source)
    assert 'html' not in function_scope_bindings(tree)[tree.body[-1]]
    assert known_python_identity_conflict(source, 3, ('html.escape',)) is None
