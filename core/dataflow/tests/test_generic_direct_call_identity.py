"""Owned direct generic receiver conflicts are not canonical library identity."""
import pytest

from core.dataflow.source_identity import known_python_identity_conflict


SOURCE = 'import html\ntype Alias[html] = html.escape("<owned>")\n'


def test_direct_generic_alias_receiver_is_not_canonical_library():
    namespace = {'__name__': 'owned_generic_direct_alias'}
    exec(compile(SOURCE, '<owned-generic-direct-alias>', 'exec', dont_inherit=True), namespace)
    alias = namespace['Alias']
    assert type(alias.__type_params__[0]).__name__ == 'TypeVar'
    with pytest.raises(AttributeError, match='escape'):
        _ = alias.__value__
    assert known_python_identity_conflict(SOURCE, 2, ('html.escape',))


@pytest.mark.parametrize('parameters', ['html', '*html', '**html'],
                         ids=['typevar', 'typevartuple', 'paramspec'])
@pytest.mark.parametrize('wrapped', [False, True], ids=['direct', 'container'])
def test_alias_value_parameter_conflict_cannot_keep_library_identity(parameters, wrapped):
    value = 'html.escape("owned")'
    if wrapped:
        value = '[' + value + ']'
    source = 'import html\ntype Alias[' + parameters + '] = ' + value + '\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',))


def test_alias_import_spelling_is_checked_against_own_parameter():
    source = 'import html as escaped\ntype Alias[escaped] = escaped.escape("owned")\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',))


def test_other_alias_parameter_keeps_existing_library_precision():
    source = 'import html\ntype Alias[other] = html.escape("owned")\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None


def test_nongeneric_alias_keeps_existing_library_precision():
    source = 'import html\ntype Alias = html.escape("<owned>")\n'
    namespace = {'__name__': 'owned_nongeneric_alias_direct'}
    exec(compile(source, '<owned-nongeneric-alias-direct>', 'exec', dont_inherit=True), namespace)
    assert namespace['Alias'].__value__ == '&lt;owned&gt;'
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None


def test_alias_parameters_do_not_poison_later_module_call():
    source = 'import html\ntype Alias[html] = int\nvalue = html.escape("owned")\n'
    assert known_python_identity_conflict(source, 3, ('html.escape',)) is None


def test_ordinary_enclosing_function_conflict_still_applies_to_alias_value():
    source = ('import html\ndef outer(html):\n'
              '    type Alias = html.escape("owned")\n    return Alias\n')
    assert known_python_identity_conflict(source, 3, ('html.escape',))


def test_alias_rhs_lambda_keeps_its_existing_scope_refusal():
    source = 'import html\ntype Alias[html] = lambda value: html.escape(value)\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',))
