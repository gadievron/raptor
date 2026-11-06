"""Display-only disable annotations require typed and unambiguous metadata."""
import json

import pytest

from core.sandbox import summary


def read(tmp_path, payload, prefix=b''):
    path = tmp_path / summary.SUMMARY_FILE
    raw = prefix + (payload.encode() if isinstance(payload, str) else json.dumps(payload).encode())
    path.write_bytes(raw)
    value = summary.read_cli_disable_annotation(tmp_path)
    assert path.read_bytes() == raw
    return value


@pytest.mark.parametrize('value', [None, 0, 1, 1.0, 'true', 'false', [], [True], {}, {'active': True}],
                         ids=['null', 'zero', 'one', 'float', 'string-true', 'string-false',
                              'empty-array', 'array', 'empty-object', 'object'])
def test_only_boolean_true_establishes_disabled_display(tmp_path, value):
    assert read(tmp_path, {'cli_sandbox_disabled': value, 'disable_consent': 'interactive-tty'}) is None


@pytest.mark.parametrize('label', [[1], {'source': 'nonce'}, 17, True, ['nonce']],
                         ids=['array', 'object', 'integer', 'boolean', 'label-array'])
def test_malformed_source_labels_fall_back_without_hiding_disabled_status(tmp_path, label):
    assert read(tmp_path, {'cli_sandbox_disabled': True, 'disable_consent': label}) == 'unrecorded'


@pytest.mark.parametrize('label', [None, '', [], {}, 0, False],
                         ids=['null', 'empty', 'array', 'object', 'zero', 'false'])
def test_empty_source_metadata_keeps_legacy_fallback(tmp_path, label):
    assert read(tmp_path, {'cli_sandbox_disabled': True, 'disable_consent': label}) == 'unrecorded'


@pytest.mark.parametrize('prefix', [b'', b'\xef\xbb\xbf'], ids=['plain', 'bom'])
@pytest.mark.parametrize('payload', [
    '{"cli_sandbox_disabled":false,"cli_sandbox_disabled":true,"disable_consent":"nonce"}',
    '{"cli_sandbox_disabled":true,"disable_consent":"first","disable_consent":"nonce"}',
    r'{"cli_sandbox_disabled":true,"disable_consent":"first","disable_\u0063onsent":"nonce"}',
    '{"cli_sandbox_disabled":true,"disable_consent":"nonce","disable_consent":"nonce"}',
    '{"cli_sandbox_disabled":true,"disable_consent":"nonce","metadata":{"x":1,"x":2}}',
], ids=['flag', 'label', 'escaped-label', 'equal-label', 'nested'])
def test_ambiguous_documents_have_no_display_annotation(tmp_path, prefix, payload):
    assert read(tmp_path, payload, prefix) is None


@pytest.mark.parametrize('prefix', [b'', b'\xef\xbb\xbf'], ids=['plain', 'bom'])
def test_unique_future_labels_and_distinct_nested_objects_remain_valid(tmp_path, prefix):
    value = {'cli_sandbox_disabled': True, 'disable_consent': 'future-source',
             'denials': [{'path': '/first'}, {'path': '/second'}]}
    assert read(tmp_path, value, prefix) == 'future-source'


def test_boolean_false_and_absent_flags_remain_unannotated(tmp_path):
    assert read(tmp_path, {'cli_sandbox_disabled': False, 'disable_consent': 'nonce'}) is None
    assert read(tmp_path, {'disable_consent': 'nonce'}) is None


def test_missing_source_remains_unrecorded(tmp_path):
    assert read(tmp_path, {'cli_sandbox_disabled': True}) == 'unrecorded'
