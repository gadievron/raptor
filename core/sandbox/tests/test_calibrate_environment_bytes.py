"""Environment fingerprints retain legacy identities and accept OS byte data."""
import hashlib
import os

import pytest

from core.sandbox import calibrate as cal


KEY = 'CAL_TEST_VALUE'


@pytest.mark.parametrize('value,payload', [('alpha', b'14:CAL_TEST_VALUE=5:alpha'),
                                         ('Caf\u00e9', b'14:CAL_TEST_VALUE=4:Caf\xc3\xa9')],
                         ids=['ascii', 'unicode'])
def test_existing_environment_fingerprints_are_unchanged(monkeypatch, value, payload):
    monkeypatch.setenv(KEY, value)
    assert cal._env_signature([KEY]) == hashlib.sha256(payload).hexdigest()


@pytest.mark.skipif(not getattr(os, 'supports_bytes_environ', False), reason='requires byte-valued POSIX environment')
@pytest.mark.parametrize('raw', [b'\xff', b'\xc3(', b'line\n\xff'], ids=['invalid-byte', 'partial-utf8', 'newline-byte'])
def test_non_utf8_environment_values_have_stable_fingerprints(monkeypatch, raw):
    monkeypatch.setitem(os.environb, KEY.encode(), raw)
    value = os.environ[KEY]
    expected = f'14:{KEY}={len(value)}:{value}'.encode('utf-8', errors='surrogateescape')
    assert cal._env_signature([KEY]) == hashlib.sha256(expected).hexdigest()


@pytest.mark.skipif(not getattr(os, 'supports_bytes_environ', False), reason='requires byte-valued POSIX environment')
def test_non_utf8_key_and_value_are_supported(monkeypatch):
    raw_key, raw_value = b'CAL_TEST_\xff', b'value-\xfe'
    monkeypatch.setitem(os.environb, raw_key, raw_value)
    key, value = os.fsdecode(raw_key), os.fsdecode(raw_value)
    payload = f'{len(key)}:{key}={len(value)}:{value}'.encode('utf-8', errors='surrogateescape')
    assert cal._env_signature([key]) == hashlib.sha256(payload).hexdigest()


@pytest.mark.skipif(not getattr(os, 'supports_bytes_environ', False), reason='requires byte-valued POSIX environment')
def test_byte_values_preserve_order_dedup_and_change_detection(monkeypatch):
    other = 'CAL_TEST_OTHER'
    monkeypatch.setitem(os.environb, KEY.encode(), b'\xff')
    monkeypatch.setenv(other, 'owned')
    first = cal._env_signature([KEY, other, KEY])
    assert first == cal._env_signature([other, KEY])
    monkeypatch.setitem(os.environb, KEY.encode(), b'\xfe')
    assert cal._env_signature([KEY, other]) != first


def test_empty_and_missing_environment_compatibility(monkeypatch):
    monkeypatch.delenv(KEY, raising=False)
    missing = cal._env_signature([KEY])
    monkeypatch.setenv(KEY, '')
    assert cal._env_signature([KEY]) == missing
    assert cal._env_signature([]) == hashlib.sha256(b'').hexdigest()
