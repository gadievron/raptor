"""Failed exclusive creations cannot leave an unusable short key forever."""
import os
from unittest.mock import Mock

import pytest

from core.sandbox import telemetry_mac as mac


import core.sandbox.telemetry_mac as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


class Cancelled(BaseException):
    pass


@pytest.fixture
def path(tmp_path, monkeypatch):
    path = tmp_path / 'key'
    monkeypatch.setattr(mac, '_key_path', lambda: path)
    return path


@pytest.mark.parametrize('failure', ['zero', 'error', 'cancel'])
@pytest.mark.parametrize('prefix', [0, 5])
def test_incomplete_creation_can_retry(path, monkeypatch, failure, prefix):
    original = os.write
    calls = 0
    error = Cancelled('cancelled write') if failure == 'cancel' else OSError('write failed')

    def write(fd, data):
        nonlocal calls
        calls += 1
        if prefix and calls == 1:
            return original(fd, data[:prefix])
        if failure == 'zero':
            return 0
        raise error

    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, _os_fault_consumer, "os", 'write', write)
        with pytest.raises(Cancelled if failure == 'cancel' else OSError):
            mac._load_or_create_key()
    assert not path.exists()
    token = mac.mint({'kind': 'test'})
    assert token
    assert mac.verify({'kind': 'test'}, token)
    assert len(path.read_bytes()) == mac._KEY_LEN


def test_complete_key_survives_cancellation_after_write(path, monkeypatch):
    original = os.write

    def write(fd, data):
        original(fd, data)
        raise Cancelled('cancelled after full write')

    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, _os_fault_consumer, "os", 'write', write)
        with pytest.raises(Cancelled):
            mac._load_or_create_key()
    key = path.read_bytes()
    assert len(key) == mac._KEY_LEN
    assert mac._load_or_create_key() == key


def test_replacement_key_is_not_removed(path, monkeypatch):
    original = os.write
    replacement = b'r' * mac._KEY_LEN

    def write(fd, data):
        original(fd, data[:3])
        other = path.with_name('replacement')
        other.write_bytes(replacement)
        other.chmod(0o600)
        other.replace(path)
        raise OSError('failed after path replacement')

    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, _os_fault_consumer, "os", 'write', write)
        with pytest.raises(OSError):
            mac._load_or_create_key()
    assert path.read_bytes() == replacement
    assert mac._load_or_create_key() == replacement


def test_cleanup_error_does_not_replace_write_error(path, monkeypatch):
    warning = Mock()
    monkeypatch.setattr(mac.logger, "warning", warning)
    original = OSError('original write failure')

    def write(*args):
        raise original

    def unlink(*args, **kwargs):
        raise OSError('cleanup failed')

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'write', write)
    monkeypatch.setattr(type(path), 'unlink', unlink)
    with pytest.raises(OSError) as raised:
        mac._load_or_create_key()
    assert raised.value is original
    assert any('incomplete key cleanup failed' in str(call) for call in warning.call_args_list)
