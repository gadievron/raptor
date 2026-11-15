"""Owned signature annotation frames remain distinct from defaults and strings."""
from typing import TypeVar

import pytest

from core.dataflow.source_identity import known_python_identity_conflict


SIGNATURES = [
    '(value: html.escape("<owned>"))',
    '(value: html.escape("<owned>"), /)',
    '(*, value: html.escape("<owned>"))',
    '(*values: html.escape("<owned>"))',
    '(**values: html.escape("<owned>"))',
    '() -> html.escape("<owned>")',
]


def _assert_annotation_receiver(source, filename, namespace, parameter_index):
    # Python 3.13 evaluates at definition; 3.14 defers until annotation access.
    with pytest.raises(AttributeError, match='escape') as failure:
        exec(compile(source, filename, 'exec', dont_inherit=True), namespace)
        _ = namespace['helper'].__annotations__
    if 'helper' in namespace:
        receiver = namespace['helper'].__type_params__[parameter_index]
    else:
        receivers = []
        traceback = failure.value.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            value = frame.f_locals.get('html')
            if frame.f_code.co_filename == filename and isinstance(value, TypeVar):
                receivers.append(value)
            traceback = traceback.tb_next
        assert len(receivers) == 1
        receiver = receivers[0]
    assert failure.value.obj is receiver


@pytest.mark.parametrize('prefix', ['def', 'async def'], ids=['function', 'async'])
@pytest.mark.parametrize('signature', SIGNATURES, ids=['argument', 'posonly', 'kwonly', 'vararg', 'kwarg', 'return'])
def test_signature_annotation_actual_parameter_requires_refusal(prefix, signature):
    source = f'import html\n{prefix} helper[html]{signature}:\n    pass\n'
    namespace = {'__name__': 'owned_signature_annotation'}
    _assert_annotation_receiver(source, '<owned-signature-annotation>', namespace, 0)
    assert known_python_identity_conflict(source, 2, ('html.escape',))


@pytest.mark.parametrize('signature', SIGNATURES, ids=['argument', 'posonly', 'kwonly', 'vararg', 'kwarg', 'return'])
def test_future_string_signature_preserves_existing_identity_profile(signature):
    source = f'from __future__ import annotations\nimport html\ndef helper[html]{signature}:\n    pass\n'
    namespace = {'__name__': 'owned_string_signature'}
    exec(compile(source, '<owned-string-signature>', 'exec', dont_inherit=True), namespace)
    assert list(namespace['helper'].__annotations__.values()) == ["html.escape('<owned>')"]
    assert known_python_identity_conflict(source, 3, ('html.escape',)) is None


@pytest.mark.parametrize('parameter', ['', '[Other]'], ids=['ordinary', 'unrelated'])
@pytest.mark.parametrize('signature', SIGNATURES, ids=['argument', 'posonly', 'kwonly', 'vararg', 'kwarg', 'return'])
def test_signature_unrelated_parameter_preserves_module_receiver(parameter, signature):
    source = f'import html\ndef helper{parameter}{signature}:\n    pass\n'
    namespace = {'__name__': 'owned_module_signature'}
    exec(compile(source, '<owned-module-signature>', 'exec', dont_inherit=True), namespace)
    assert list(namespace['helper'].__annotations__.values()) == ['&lt;owned&gt;']
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None


def test_local_variable_annotation_remains_nonexecuting():
    source = 'import html\ndef helper[html]():\n    value: html.escape("<owned>")\n    return None\n'
    namespace = {'__name__': 'owned_local_annotation'}
    exec(compile(source, '<owned-local-annotation>', 'exec', dont_inherit=True), namespace)
    assert namespace['helper']() is None
    assert namespace['helper'].__annotations__ == {}
    assert known_python_identity_conflict(source, 3, ('html.escape',))


@pytest.mark.parametrize('prefix', ['def', 'async def'], ids=['function', 'async'])
def test_cross_parameter_signature_receiver_requires_refusal(prefix):
    source = f'import html\n{prefix} helper[Other, html](value: html.escape("<owned>")):\n    pass\n'
    namespace = {'__name__': 'owned_cross_parameter_signature'}
    _assert_annotation_receiver(source, '<owned-cross-parameter-signature>', namespace, 1)
    assert known_python_identity_conflict(source, 2, ('html.escape',))


@pytest.mark.parametrize('prefix', ['def', 'async def'], ids=['function', 'async'])
def test_signature_annotation_uses_written_import_spelling(prefix):
    source = f'import html as escaped\n{prefix} helper[escaped](value: escaped.escape("owned")):\n    pass\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',))


def test_async_future_string_signature_preserves_existing_identity_profile():
    source = ('from __future__ import annotations\nimport html\n'
              'async def helper[html]() -> html.escape("<owned>"):\n    pass\n')
    namespace = {'__name__': 'owned_async_string_signature'}
    exec(compile(source, '<owned-async-string-signature>', 'exec', dont_inherit=True), namespace)
    assert namespace['helper'].__annotations__ == {'return': "html.escape('<owned>')"}
    assert known_python_identity_conflict(source, 3, ('html.escape',)) is None


def test_signature_parameter_does_not_leak_to_module_call():
    source = ('import html\ndef helper[html](value: html.escape("owned")):\n    pass\n'
              'value = html.escape("owned")\n')
    assert known_python_identity_conflict(source, 4, ('html.escape',)) is None


def test_eager_definition_failure_preserves_type_parameter_identity():
    source = 'import html\nclass helper[html](html.escape("<owned>")):\n    pass\n'
    namespace = {'__name__': 'owned_eager_definition'}
    _assert_annotation_receiver(source, '<owned-eager-definition>', namespace, 0)
    assert 'helper' not in namespace
