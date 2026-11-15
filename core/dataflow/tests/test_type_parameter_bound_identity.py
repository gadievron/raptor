"""Owned CPython lazy bound receivers precede source-identity assertions."""
import pytest

from core.dataflow.source_identity import known_python_identity_conflict


SOURCE = 'import html\ndef helper[html: html.escape("<owned>")]():\n    pass\n'


def test_lazy_function_bound_receiver_matches_source_identity(record_property):
    namespace = {'__name__': 'owned_type_parameter_bound'}
    exec(compile(SOURCE, '<owned-type-parameter-bound>', 'exec', dont_inherit=True), namespace)
    parameter = namespace['helper'].__type_params__[0]
    try:
        value = parameter.__bound__
    except AttributeError as failure:
        assert failure.obj is parameter
        receiver_is_parameter = True
    else:
        assert value == '&lt;owned&gt;'
        receiver_is_parameter = False
    record_property('owned_bound_receiver', 'type-parameter' if receiver_is_parameter else 'module-root')
    conflict = known_python_identity_conflict(SOURCE, 2, ('html.escape',))
    assert bool(conflict) is receiver_is_parameter


@pytest.mark.parametrize('prefix', ['def', 'async def'], ids=['function', 'async-function'])
@pytest.mark.parametrize('parameters', [
    'html: html.escape("owned")',
    'html, Other: html.escape("owned")',
    'html: (html.escape("owned"), str)',
], ids=['self-bound', 'other-bound', 'constraint-tuple'])
def test_function_bound_parameter_receiver_refuses_library_identity(prefix, parameters):
    source = 'import html\n' + prefix + ' helper[' + parameters + ']():\n    pass\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',))


def test_bound_keeps_written_import_spelling():
    source = 'import html as escaped\ndef helper[escaped: escaped.escape("owned")]():\n    pass\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',))


def test_function_body_global_does_not_change_bound_parameter_frame():
    source = 'import html\ndef helper[html: html.escape("owned")]():\n    global html\n    pass\n'
    namespace = {'__name__': 'owned_bound_global_fixture'}
    exec(compile(source, '<owned-bound-global>', 'exec', dont_inherit=True), namespace)
    parameter = namespace['helper'].__type_params__[0]
    with pytest.raises(AttributeError, match='escape') as failure:
        _ = parameter.__bound__
    assert failure.value.obj is parameter
    assert known_python_identity_conflict(source, 2, ('html.escape',))


def test_function_default_keeps_defining_module_receiver():
    source = 'import html\ndef helper[html](value=html.escape("<owned>")):\n    return value\n'
    namespace = {'__name__': 'owned_bound_default_control'}
    exec(compile(source, '<owned-bound-default-control>', 'exec', dont_inherit=True), namespace)
    assert namespace['helper']() == '&lt;owned&gt;'
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None


def test_decorator_keeps_defining_module_receiver():
    source = ('import html\ndef capture(value):\n    return lambda fn: fn\n'
              '@capture(html.escape("owned"))\ndef helper[html]():\n    pass\n')
    assert known_python_identity_conflict(source, 4, ('html.escape',)) is None


def test_other_bound_does_not_shadow_module_receiver():
    source = 'import html\ndef helper[T: html.escape("owned")]():\n    pass\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None


def test_plain_annotation_keeps_its_existing_identity_profile():
    source = 'import html\ndef helper(value: html.escape("owned")):\n    pass\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None
