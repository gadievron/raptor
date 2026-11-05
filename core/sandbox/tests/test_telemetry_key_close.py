"""Descriptor-close errors cannot discard key reads or replace write failures."""
import os

import pytest

from core.sandbox import telemetry_mac as mac


class Cancelled(BaseException):
    pass


@pytest.fixture
def key_path(tmp_path, monkeypatch):
    path = tmp_path / 'key'
    monkeypatch.setattr(mac, '_key_path', lambda: path)
    return path


@pytest.fixture
def failing_close(monkeypatch):
    original = os.close
    closed = []

    def close(fd):
        original(fd)
        closed.append(fd)
        raise OSError('secondary close failure')

    monkeypatch.setattr(os, 'close', close)
    return closed


def test_read_close_error_keeps_healthy_key(key_path, failing_close):
    key = b'k' * mac._KEY_LEN
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    assert mac._read_existing_key(key_path) == key
    assert len(failing_close) == 1
    assert mac.key_usable()
    token = mac.mint({'kind': 'test'})
    assert token
    assert mac.verify({'kind': 'test'}, token)
    assert key_path.read_bytes() == key


def test_read_close_error_keeps_metadata_refusal(key_path, failing_close):
    key_path.write_bytes(b'k' * mac._KEY_LEN)
    key_path.chmod(0o644)
    assert isinstance(mac._read_existing_key(key_path), mac._TamperedKey)
    assert len(failing_close) == 1


@pytest.mark.parametrize('failure', [OSError, Cancelled])
def test_read_failure_is_not_replaced_by_close(key_path, monkeypatch, failing_close, failure):
    key_path.write_bytes(b'k' * mac._KEY_LEN)
    key_path.chmod(0o600)
    error = failure('original read failure')

    def read(*args):
        raise error

    monkeypatch.setattr(os, 'read', read)
    if failure is OSError:
        assert mac._read_existing_key(key_path) is None
    else:
        with pytest.raises(Cancelled) as raised:
            mac._read_existing_key(key_path)
        assert raised.value is error
    assert len(failing_close) == 1


@pytest.mark.parametrize('failure', [OSError, Cancelled])
def test_creation_write_failure_survives_close(key_path, monkeypatch, failing_close, failure):
    error = failure('original write failure')

    def write(*args):
        raise error

    monkeypatch.setattr(os, 'write', write)
    with pytest.raises(failure) as raised:
        mac._load_or_create_key()
    assert raised.value is error
    assert len(failing_close) == 1


def test_successful_creation_still_reports_close_error(key_path, failing_close):
    with pytest.raises(OSError, match='secondary close failure'):
        mac._load_or_create_key()
    assert len(failing_close) == 1
    assert len(key_path.read_bytes()) == mac._KEY_LEN
