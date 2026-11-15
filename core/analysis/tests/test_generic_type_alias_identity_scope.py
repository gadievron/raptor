"""Owned deferred TypeAlias RHS identity visibility witnesses."""
import ast

import pytest

from core.analysis.python_module_callgraph import function_scope_bindings, local_binding_names
from core.dataflow.source_identity import known_python_identity_conflict


SOURCE = ("html = 'owned-module-root'\n"
          "type Alias[html] = lambda: html\n")


def test_deferred_alias_rhs_lambda_sees_type_parameter_identity():
    namespace = {'__name__': 'owned_generic_alias_fixture'}
    exec(compile(SOURCE, '<owned-generic-alias>', 'exec', dont_inherit=True), namespace)
    alias = namespace['Alias']
    assert alias.__value__() is alias.__type_params__[0]
    assert namespace['html'] == 'owned-module-root'
    tree = ast.parse(SOURCE)
    expression = tree.body[-1].value
    assert isinstance(expression, ast.Lambda)
    assert 'html' not in local_binding_names(expression)
    assert 'html' in function_scope_bindings(tree)[expression]


@pytest.mark.parametrize('parameters', ['html', '*html', '**html'],
                         ids=['typevar', 'typevartuple', 'paramspec'])
def test_alias_rhs_parameter_identity_refuses_canonical_library(parameters):
    source = 'import html\ntype Alias[' + parameters + '] = lambda value: html.escape(value)\n'
    tree = ast.parse(source)
    expression = tree.body[-1].value
    assert 'html' not in local_binding_names(expression)
    assert 'html' in function_scope_bindings(tree)[expression]
    assert known_python_identity_conflict(source, 2, ('html.escape',)) == 'source library root is locally shadowed'


def test_scope_walk_does_not_evaluate_deferred_alias_rhs():
    source = ("events = []\n"
              "type Alias[html] = (events.append('owned-evaluated'), lambda: html)[1]\n")
    namespace = {'__name__': 'owned_alias_deferred_fixture'}
    exec(compile(source, '<owned-alias-deferred>', 'exec', dont_inherit=True), namespace)
    assert namespace['events'] == []
    tree = ast.parse(source)
    expression = next(node for node in ast.walk(tree.body[-1].value) if isinstance(node, ast.Lambda))
    assert 'html' in function_scope_bindings(tree)[expression]
    assert namespace['events'] == []
    alias = namespace['Alias']
    value = alias.__value__
    assert namespace['events'] == ['owned-evaluated']
    assert value() is alias.__type_params__[0]


def test_alias_parameter_does_not_leak_to_sibling_expression():
    tree = ast.parse('type Alias[html] = lambda: html\nsibling = lambda: html\n')
    scopes = function_scope_bindings(tree)
    assert 'html' in scopes[tree.body[0].value]
    assert 'html' not in scopes[tree.body[1].value]


def test_nongeneric_alias_retains_enclosing_generic_function_frame():
    source = ('def outer[html]():\n    type Alias = lambda: html\n    return Alias\n')
    namespace = {'__name__': 'owned_alias_enclosing_fixture'}
    exec(compile(source, '<owned-alias-enclosing>', 'exec', dont_inherit=True), namespace)
    outer = namespace['outer']
    assert outer().__value__() is outer.__type_params__[0]
    tree = ast.parse(source)
    expression = tree.body[0].body[0].value
    assert 'html' in function_scope_bindings(tree)[expression]


def test_generic_alias_in_class_uses_own_parameter_frame():
    source = ('class Holder:\n    html = "owned-class-local"\n'
              '    type Alias[html] = lambda: html\n')
    namespace = {'__name__': 'owned_alias_class_fixture'}
    exec(compile(source, '<owned-alias-class>', 'exec', dont_inherit=True), namespace)
    alias = namespace['Holder'].Alias
    assert alias.__value__() is alias.__type_params__[0]
    tree = ast.parse(source)
    expression = tree.body[0].body[-1].value
    assert 'html' in function_scope_bindings(tree)[expression]


def test_nongeneric_alias_keeps_module_identity_precision():
    source = 'import html\ntype Alias = lambda value: html.escape(value)\n'
    tree = ast.parse(source)
    assert 'html' not in function_scope_bindings(tree)[tree.body[-1].value]
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None


def test_alias_lambda_defaults_and_nested_body_keep_alias_frame():
    source = 'type Alias[html] = lambda value=(lambda: html): (lambda: html)\n'
    namespace = {'__name__': 'owned_alias_lambda_frames'}
    exec(compile(source, '<owned-alias-lambda-frames>', 'exec', dont_inherit=True), namespace)
    alias = namespace['Alias']
    factory = alias.__value__
    assert factory.__defaults__[0]() is alias.__type_params__[0]
    assert factory()() is alias.__type_params__[0]
    tree = ast.parse(source)
    expressions = [node for node in ast.walk(tree.body[0].value) if isinstance(node, ast.Lambda)]
    assert len(expressions) == 3
    scopes = function_scope_bindings(tree)
    assert all('html' in scopes[node] for node in expressions)


def test_alias_scope_walk_keeps_bound_expressions_outside_added_map():
    tree = ast.parse('type Alias[html: (lambda: html)] = lambda: html\n')
    alias = tree.body[0]
    bound = alias.type_params[0].bound
    scopes = function_scope_bindings(tree)
    assert bound not in scopes
    assert 'html' in scopes[alias.value]
