"""Type-parameter defaults have distinct receiver scope from argument defaults."""
import pytest

from core.dataflow.source_identity import known_python_identity_conflict


@pytest.mark.parametrize('definition,name', [
    ('def helper[{parameters}]():\n    pass\n', 'helper'),
    ('class Holder[{parameters}]:\n    pass\n', 'Holder'),
    ('type Alias[{parameters}] = int\n', 'Alias'),
], ids=['function', 'class', 'alias'])
@pytest.mark.parametrize('parameters', [
    'html = html.escape("<owned>")',
    'html, Other = html.escape("<owned>")',
], ids=['own', 'earlier'])
def test_default_receiver_parameter_requires_identity_refusal(definition, name, parameters):
    source = 'import html\n' + definition.format(parameters=parameters)
    namespace = {'__name__': 'owned_parameter_default_identity'}
    exec(compile(source, '<owned-parameter-default>', 'exec', dont_inherit=True), namespace)
    runtime_parameters = namespace[name].__type_params__
    with pytest.raises(AttributeError, match='escape') as failure:
        _ = runtime_parameters[-1].__default__
    assert failure.value.obj is runtime_parameters[0]
    assert known_python_identity_conflict(source, 2, ('html.escape',))


@pytest.mark.parametrize('definition,name', [
    ('def helper[Other = html.escape("<owned>")]():\n    pass\n', 'helper'),
    ('class Holder[Other = html.escape("<owned>")]:\n    pass\n', 'Holder'),
    ('type Alias[Other = html.escape("<owned>")] = int\n', 'Alias'),
], ids=['function', 'class', 'alias'])
def test_default_unrelated_parameter_preserves_module_receiver(definition, name):
    source = 'import html\n' + definition
    namespace = {'__name__': 'owned_module_default_identity'}
    exec(compile(source, '<owned-module-default>', 'exec', dont_inherit=True), namespace)
    assert namespace[name].__type_params__[0].__default__ == '&lt;owned&gt;'
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None


@pytest.mark.parametrize('definition', [
    'def helper[escaped = escaped.escape("owned")]():\n    pass\n',
    'class Holder[escaped = escaped.escape("owned")]:\n    pass\n',
    'type Alias[escaped = escaped.escape("owned")] = int\n',
])
def test_parameter_default_uses_written_import_spelling(definition):
    assert known_python_identity_conflict('import html as escaped\n' + definition, 2, ('html.escape',))


def test_parameter_defaults_do_not_leak_to_module_calls():
    source = ('import html\ndef helper[html = int]():\n    pass\n'
              'class Holder[html = int]:\n    pass\n'
              'type Alias[html = int] = int\nvalue = html.escape("owned")\n')
    assert known_python_identity_conflict(source, 7, ('html.escape',)) is None
