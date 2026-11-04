"""Worker-status failures follow normal cleanup and startup recovery."""
import errno
from unittest.mock import Mock

import pytest

from core.sandbox import parser_jail as jail


def unhealthy_worker(monkeypatch):
    owner = jail.ParserJail()
    process = Mock()
    process.poll.side_effect = OSError(errno.EIO, 'status unavailable')
    socket = Mock()
    owner._proc, owner._sock = process, socket
    reap = Mock()
    monkeypatch.setattr(owner, '_reap_locked', reap)
    return owner, process, socket, reap


def test_status_failure_cleans_old_worker_before_replacement(monkeypatch):
    owner, process, socket, reap = unhealthy_worker(monkeypatch)
    replacement = Mock()
    replacement.poll.return_value = None
    replacement_socket = Mock()

    def spawn():
        assert owner._proc is None and owner._sock is None
        socket.close.assert_called_once_with()
        reap.assert_called_once_with(process)
        owner._proc, owner._sock = replacement, replacement_socket

    monkeypatch.setattr(owner, '_spawn_worker_locked', spawn)
    owner.start()
    assert owner._proc is replacement
    assert owner._sock is replacement_socket
    assert owner._spawn_failures == 0


def test_failed_replacement_remains_typed_and_backs_off(monkeypatch):
    monkeypatch.setattr(jail.time, "monotonic", lambda: 100.0)
    owner, process, socket, reap = unhealthy_worker(monkeypatch)
    failure = jail.ParserJailUnavailable('replacement unavailable')
    spawn = Mock(side_effect=failure)
    monkeypatch.setattr(owner, '_spawn_worker_locked', spawn)
    with pytest.raises(jail.ParserJailUnavailable) as caught:
        owner.start()
    assert caught.value is failure
    assert owner._proc is None and owner._sock is None
    socket.close.assert_called_once_with()
    reap.assert_called_once_with(process)
    assert owner._spawn_failures == 1
    with pytest.raises(jail.ParserJailUnavailable, match='backing off'):
        owner.start()
    assert spawn.call_count == 1


def test_healthy_worker_is_reused(monkeypatch):
    owner = jail.ParserJail()
    owner._proc = Mock()
    owner._proc.poll.return_value = None
    owner._sock = Mock()
    spawn = Mock()
    monkeypatch.setattr(owner, '_spawn_worker_locked', spawn)
    owner.start()
    spawn.assert_not_called()
    owner._sock.close.assert_not_called()


def test_stopped_owner_does_not_poll_or_respawn(monkeypatch):
    owner, process, socket, reap = unhealthy_worker(monkeypatch)
    owner._stopped = True
    with pytest.raises(jail.ParserJailUnavailable, match='stopped'):
        owner.start()
    process.poll.assert_not_called()
    reap.assert_not_called()
