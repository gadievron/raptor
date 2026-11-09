"""Strict numeric admission across shared readers and status consumers."""
import math

import pytest

from core.json import bounded, jsonc, utils
from core.json.jsonl import load_jsonl
from core.run import digest
from core.testing.module_state import isolated_module_state


@pytest.fixture(params=['stdlib', 'native'])
def backend(request):
    native = None if request.param == 'stdlib' else pytest.importorskip('orjson')
    with isolated_module_state(utils, {'_orjson': native}):
        yield


def read_document(mode, text, tmp_path):
    path = tmp_path / 'owned.json'
    path.write_text(text, encoding='utf-8')
    if mode == 'text':
        return utils.loads(text)
    if mode == 'bytes':
        return utils.loads(text.encode())
    if mode == 'bytearray':
        return utils.loads(bytearray(text.encode()))
    if mode == 'hook':
        return utils.loads(text, object_pairs_hook=dict)
    if mode == 'bounded-text':
        return bounded.loads_bounded(text, max_bytes=4096)
    if mode == 'bounded-file':
        return bounded.load_json_bounded(path, max_bytes=4096)
    if mode == 'jsonc':
        return jsonc.load_jsonc(text)
    if mode == 'file':
        return utils.load_json(path, strict=True)
    return utils.load_json_with_comments(path, object_pairs_hook=dict)


MODES = ['text', 'hook', 'bounded-text', 'bounded-file', 'jsonc', 'file', 'comments', 'bytes', 'bytearray']


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('token', ['1e999', '-1e999', '9.5e309'])
def test_strict_readers_reject_exponent_overflow(backend, mode, token, tmp_path):
    text = '{"nested":{"value":' + token + '}}'
    if mode == 'comments':
        assert read_document(mode, text, tmp_path) is None
    else:
        with pytest.raises(ValueError):
            read_document(mode, text, tmp_path)


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('token', ['1e308', '-1e308', '1.5e-3', '5e-324', '1e-999', '-0.0'])
def test_strict_readers_preserve_finite_numbers(backend, mode, token, tmp_path):
    result = read_document(mode, '{"value":' + token + ',"quoted":"1e999"}', tmp_path)
    assert result == {'value': float(token), 'quoted': '1e999'}
    assert math.copysign(1, result['value']) == math.copysign(1, float(token))


@pytest.mark.parametrize('hook', [None, dict])
@pytest.mark.parametrize('token', ['1e999', '-1e999'])
def test_explicit_permissive_policy_retains_overflow(backend, hook, token, tmp_path):
    text = '{"value":' + token + '}'
    assert math.isinf(utils.loads(text, allow_non_finite=True, object_pairs_hook=hook)['value'])
    path = tmp_path / 'trusted.json'
    path.write_text(text, encoding='utf-8')
    assert math.isinf(utils.load_json(path, allow_non_finite=True)['value'])


@pytest.mark.parametrize('max_records', [None, 1])
def test_jsonl_keeps_valid_neighbours_and_valid_record_totals(backend, max_records, tmp_path, caplog):
    path = tmp_path / 'owned.jsonl'
    path.write_text('{"value":1}\n{"value":1e999}\n{"value":2}\n', encoding='utf-8')
    expected = [{'value': 1}, {'value': 2}] if max_records is None else [{'value': 2}]
    assert load_jsonl(path, max_records=max_records) == expected
    if max_records == 1:
        assert 'newest 1 of 2' in caplog.text


@pytest.mark.parametrize('token,expected', [('1e999', None), ('1.5e1', 15.0)])
def test_metadata_numeric_admission_preserves_status_rendering(backend, token, expected, tmp_path):
    (tmp_path / '.raptor-run.json').write_text(
        '{"command":"scan","status":"completed","duration_seconds":' + token + '}',
        encoding='utf-8',
    )
    result = digest.RunDigest(tmp_path)
    digest._read_lifecycle(result)
    assert 'Status:' in digest.render_run_status(result)
    assert result.duration_seconds == expected


@pytest.mark.parametrize('mode', ['bounded-text', 'bounded-file', 'hook', 'comments'])
def test_exact_large_integers_remain_exact(mode, tmp_path):
    integer = 2 ** 100 + 123
    assert read_document(mode, '{"value":' + str(integer) + '}', tmp_path) == {'value': integer}
