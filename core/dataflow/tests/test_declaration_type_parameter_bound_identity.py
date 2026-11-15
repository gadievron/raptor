"""Owned CPython class/alias bound receivers qualify identity expectations."""
import pytest

from core.dataflow.source_identity import known_python_identity_conflict


@pytest.mark.parametrize('definition,name', [
    ('class Holder[html: html.escape("<owned>")]:\n    pass\n', 'Holder'),
    ('type Alias[html: html.escape("<owned>")] = int\n', 'Alias'),
], ids=['class-bound', 'alias-bound'])
def test_lazy_declaration_bound_receiver_matches_source_identity(definition, name, record_property):
    source = 'import html\n' + definition
    namespace = {'__name__': 'owned_declaration_bound'}
    exec(compile(source, '<owned-declaration-bound>', 'exec', dont_inherit=True), namespace)
    parameter = namespace[name].__type_params__[0]
    try:
        value = parameter.__bound__
    except AttributeError as failure:
        assert failure.obj is parameter
        receiver_is_parameter = True
    else:
        assert value == '&lt;owned&gt;'
        receiver_is_parameter = False
    record_property('owned_declaration_bound_receiver', 'type-parameter' if receiver_is_parameter else 'module-root')
    assert bool(known_python_identity_conflict(source, 2, ('html.escape',))) is receiver_is_parameter


@pytest.mark.parametrize('template', [
    'class Holder[{parameters}]:\n    pass\n',
    'type Alias[{parameters}] = int\n',
], ids=['class', 'alias'])
@pytest.mark.parametrize('parameters', [
    'html: html.escape("owned")',
    'html, Other: html.escape("owned")',
    'html: (html.escape("owned"), str)',
], ids=['self-bound', 'other-bound', 'constraint-tuple'])
def test_declaration_bound_parameter_refuses_library_identity(template, parameters):
    source = 'import html\n' + template.format(parameters=parameters)
    assert known_python_identity_conflict(source, 2, ('html.escape',))


@pytest.mark.parametrize('definition', [
    'class Holder[escaped: escaped.escape("owned")]:\n    pass\n',
    'type Alias[escaped: escaped.escape("owned")] = int\n',
], ids=['class', 'alias'])
def test_declaration_bound_uses_written_import_spelling(definition):
    assert known_python_identity_conflict('import html as escaped\n' + definition, 2, ('html.escape',))


def test_class_body_global_does_not_remove_its_bound_frame():
    source = 'import html\nclass Holder[html: html.escape("owned")]:\n    global html\n    pass\n'
    namespace = {'__name__': 'owned_class_bound_global'}
    exec(compile(source, '<owned-class-bound-global>', 'exec', dont_inherit=True), namespace)
    parameter = namespace['Holder'].__type_params__[0]
    with pytest.raises(AttributeError, match='escape') as failure:
        _ = parameter.__bound__
    assert failure.value.obj is parameter
    assert known_python_identity_conflict(source, 2, ('html.escape',))


@pytest.mark.parametrize('definition', [
    'class Holder[Other: html.escape("owned")]:\n    pass\n',
    'type Alias[Other: html.escape("owned")] = int\n',
], ids=['class', 'alias'])
def test_other_declaration_parameter_preserves_module_identity(definition):
    assert known_python_identity_conflict('import html\n' + definition, 2, ('html.escape',)) is None


def test_declaration_bound_parameters_do_not_leak_to_later_call():
    source = ('import html\nclass Holder[html: int]:\n    pass\n'
              'type Alias[html: int] = int\nvalue = html.escape("owned")\n')
    assert known_python_identity_conflict(source, 5, ('html.escape',)) is None
