"""Owned CPython witnesses for generic class method identity visibility."""
import ast

import pytest

from core.analysis.python_module_callgraph import (
    function_scope_bindings, local_binding_names, module_distrusted_roots,
)
from core.dataflow.source_identity import known_python_identity_conflict


SOURCE = ("html = 'owned-module-root'\n"
          "class Holder[html]:\n"
          "    def helper(self):\n"
          "        return html\n")


def test_generic_class_method_sees_type_parameter_identity():
    namespace = {'__name__': 'owned_generic_class_fixture'}
    exec(compile(SOURCE, '<owned-generic-class>', 'exec', dont_inherit=True), namespace)
    holder = namespace['Holder']
    assert holder().helper() is holder.__type_params__[0]
    assert namespace['html'] == 'owned-module-root'
    tree = ast.parse(SOURCE)
    method = tree.body[-1].body[0]
    assert 'html' not in local_binding_names(method)
    assert 'html' in function_scope_bindings(tree)[method]


def test_generic_class_runtime_lookup_contract():
    cases = {
        'class-local': ('class Holder[html]:\n    html = "owned-class-local"\n'
                        '    def helper(self):\n        return html\n',
                        'Holder().helper()'),
        'class-global': ('class Holder[html]:\n    global html\n'
                         '    def helper(self):\n        return html\n',
                         'Holder().helper()'),
        'method-global': ('class Holder[html]:\n'
                          '    def helper(self):\n        global html\n        return html\n',
                          'Holder().helper()'),
        'method-default': ('class Holder[html]:\n'
                           '    def helper(self, value=(lambda: html)()):\n        return value\n',
                           'Holder().helper()'),
        'class-keyword': ('class Meta(type):\n'
                          '    def __new__(meta, name, bases, namespace, **options):\n'
                          '        result = super().__new__(meta, name, bases, namespace)\n'
                          '        result.observed = options["tag"]\n'
                          '        return result\n'
                          'class Holder[html](metaclass=Meta, tag=(lambda: html)()):\n    pass\n',
                          'Holder.observed'),
        'class-base': ('class Holder[html]((lambda: list[html])()):\n    pass\n',
                       'Holder.__orig_bases__[0].__args__[0]'),
        'class-decorator': ('seen = []\ndef capture(value):\n    seen.append(value)\n'
                            '    return lambda cls: cls\n@capture(html)\nclass Holder[html]:\n    pass\n',
                            'seen[0]'),
        'nested-class': ('class Holder[html]:\n    class Inner:\n'
                         '        def helper(self):\n            return html\n',
                         'Holder.Inner().helper()'),
    }
    observations = {}
    for name, (definition, projection) in cases.items():
        namespace = {'__name__': 'owned_generic_class_lookup'}
        try:
            source = "html = 'owned-module-root'\n" + definition + 'observed = ' + projection + '\n'
            exec(compile(source, '<owned-generic-class-lookup>', 'exec', dont_inherit=True), namespace)
        except (SyntaxError, TypeError) as error:
            observations[name] = {'outcome': type(error).__name__, 'message': str(error)}
            continue
        value = namespace['observed']
        if value is namespace['Holder'].__type_params__[0]:
            outcome = 'class-type-parameter'
        elif value == 'owned-module-root':
            outcome = 'module-root'
        elif value == 'owned-class-local':
            outcome = 'class-local'
        else:
            outcome = 'other'
        observations[name] = {'outcome': outcome}
        assert outcome != 'other'
    assert set(observations) == set(cases)
    expected = {name: {'outcome': 'class-type-parameter'} for name in cases}
    expected['class-decorator'] = {'outcome': 'module-root'}
    expected['method-global'] = {'outcome': 'module-root'}
    assert observations == expected


@pytest.mark.parametrize('parameters', ['html', '*html', '**html'],
                         ids=['typevar', 'typevartuple', 'paramspec'])
@pytest.mark.parametrize('prefix', ['def', 'async def'], ids=['method', 'async-method'])
def test_generic_class_method_refusal_keeps_ordinary_bindings_separate(parameters, prefix):
    source = ('import html\nclass Holder[' + parameters + ']:\n'
              '    other = replacement\n    ' + prefix + ' helper(self, value):\n'
              '        return html.escape(value)\n')
    tree = ast.parse(source)
    method = tree.body[-1].body[-1]
    visible = function_scope_bindings(tree)[method]
    assert 'html' in visible
    assert 'other' not in visible
    assert 'html' not in local_binding_names(method)
    assert 'html' not in module_distrusted_roots(tree)
    assert known_python_identity_conflict(source, 5, ('html.escape',)) == 'source library root is locally shadowed'


def test_generic_class_header_and_method_default_scopes_are_distinct():
    source = ('@(lambda: html)\n'
              'class Holder[html]((lambda: list[html])(), tag=(lambda: html)()):\n'
              '    def helper(self, value=(lambda: html)()):\n        return html\n')
    tree = ast.parse(source)
    holder = tree.body[0]
    decorator = holder.decorator_list[0]
    base = holder.bases[0].func
    keyword = holder.keywords[0].value.func
    default = holder.body[0].args.defaults[0].func
    scopes = function_scope_bindings(tree)
    assert 'html' not in scopes[decorator]
    assert all('html' in scopes[node] for node in (base, keyword, default))


def test_class_level_global_does_not_remove_method_type_parameter_frame():
    tree = ast.parse('class Holder[html]:\n    global html\n'
                     '    def helper(self):\n        return html\n')
    assert 'html' in function_scope_bindings(tree)[tree.body[0].body[-1]]


def test_method_global_removes_type_parameter_from_descendant_visibility():
    tree = ast.parse('class Holder[html]:\n'
                     '    def helper(self):\n        global html\n'
                     '        def nested():\n            return html\n        return nested()\n')
    scopes = function_scope_bindings(tree)
    method = tree.body[0].body[0]
    assert 'html' not in scopes[method]
    assert 'html' not in scopes[method.body[1]]


def test_nested_class_keeps_annotation_frame_without_class_locals():
    tree = ast.parse('class Holder[html]:\n    other = replacement\n    class Inner:\n'
                     '        inner = replacement\n        def helper(self):\n            return html\n')
    method = tree.body[0].body[1].body[1]
    visible = function_scope_bindings(tree)[method]
    assert 'html' in visible
    assert not {'other', 'inner'} & visible


def test_nongeneric_class_assignments_do_not_shadow_method_module_identity():
    source = ('import html\nclass Holder:\n    html = replacement\n'
              '    def helper(self, value):\n        return html.escape(value)\n')
    tree = ast.parse(source)
    assert 'html' not in function_scope_bindings(tree)[tree.body[-1].body[-1]]
    assert known_python_identity_conflict(source, 5, ('html.escape',)) is None
