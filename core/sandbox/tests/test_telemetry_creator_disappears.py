"""A waiting creator can recover when the exclusive-create winner fails."""
import os
import threading

import pytest

from core.sandbox import telemetry_mac as mac

from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('prefix', [0, 5])
def test_waiting_caller_recovers_failed_creator(tmp_path, monkeypatch, prefix):
    key_path = tmp_path / 'key'
    monkeypatch.setattr(mac, '_key_path', lambda: key_path)
    original_write = os.write
    partial_ready, release_failure, winner_done = (threading.Event() for _ in range(3))
    failures = []

    def write(fd, data):
        if threading.current_thread() is winner:
            if prefix:
                original_write(fd, data[:prefix])
            partial_ready.set()
            assert release_failure.wait(2)
            raise OSError('exclusive creator failed')
        return original_write(fd, data)

    def creator():
        try:
            mac._load_or_create_key()
        except OSError as error:
            failures.append(str(error))
        finally:
            winner_done.set()

    def allow_failed_creator_to_exit(seconds):
        release_failure.set()
        assert winner_done.wait(2)

    winner = threading.Thread(target=creator, name='failing-key-creator')
    monkeypatch.setattr(os, 'write', write)
    patch_module_attribute(monkeypatch, mac, "time", 'sleep', allow_failed_creator_to_exit)
    try:
        winner.start()
        assert partial_ready.wait(2)
        recovered = mac._load_or_create_key()
        assert failures == ['exclusive creator failed']
        assert recovered is not None
        assert len(recovered) == mac._KEY_LEN
        assert key_path.read_bytes() == recovered
        token = mac.mint({'kind': 'test'})
        assert mac.verify({'kind': 'test'}, token)
    finally:
        release_failure.set()
        winner.join(3)
        assert not winner.is_alive()


def test_repeated_missing_winners_have_bounded_creation_attempts(tmp_path, monkeypatch):
    monkeypatch.setattr(mac, '_key_path', lambda: tmp_path / 'key')
    monkeypatch.setattr(mac, '_read_existing_key', lambda path: None)
    patch_module_attribute(monkeypatch, mac, "time", 'sleep', lambda seconds: None)
    attempts = []

    def lose_creation(*args, **kwargs):
        attempts.append(args)
        raise FileExistsError('another creator raced')

    monkeypatch.setattr(os, 'open', lose_creation)
    assert mac._load_or_create_key() is None
    assert len(attempts) == 2


def test_transient_read_errors_keep_existing_retry_budget(tmp_path, monkeypatch):
    key_path = tmp_path / 'key'
    key = b'k' * mac._KEY_LEN
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    monkeypatch.setattr(mac, '_key_path', lambda: key_path)
    original_read = mac._read_existing_key
    reads = []

    def unreadable_then_healthy(path):
        reads.append(path)
        if len(reads) <= 5:
            return None  # the existing reader's host-I/O failure result
        return original_read(path)

    monkeypatch.setattr(mac, '_read_existing_key', unreadable_then_healthy)
    patch_module_attribute(monkeypatch, mac, "time", 'sleep', lambda seconds: None)
    assert mac._load_or_create_key() == key
    assert len(reads) == 6
    assert key_path.read_bytes() == key


def test_unreadable_existing_key_does_not_repeat_creation_budget(tmp_path, monkeypatch):
    key_path = tmp_path / 'key'
    key = b'k' * mac._KEY_LEN
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    monkeypatch.setattr(mac, '_key_path', lambda: key_path)
    monkeypatch.setattr(mac, '_read_existing_key', lambda path: None)
    patch_module_attribute(monkeypatch, mac, "time", 'sleep', lambda seconds: None)
    original_open = os.open
    attempts = []

    def open_key(*args, **kwargs):
        attempts.append(args)
        return original_open(*args, **kwargs)

    monkeypatch.setattr(os, 'open', open_key)
    assert mac._load_or_create_key() is None
    assert len(attempts) == 1
    assert key_path.read_bytes() == key
