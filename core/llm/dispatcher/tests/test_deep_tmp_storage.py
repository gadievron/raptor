"""Deep temporary bases must not force credential IPC into host /tmp."""
import errno
import os
from pathlib import Path
import sys
import tempfile

import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.server import LLMDispatcher

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux procfs socket address')


def test_deep_socket_storage_stays_owned_and_pin_closes_at_shutdown(tmp_path, monkeypatch):
    base = tmp_path / ('selected-base-' + 'x' * 100)
    base.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(base))
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {}
    dispatcher = LLMDispatcher(run_id='deep-owned', creds=creds)
    storage = dispatcher._sock_dir
    descriptor = int(dispatcher.socket_path.parent.name)
    try:
        assert storage.parent == base
        assert dispatcher.socket_path.resolve() == storage / 'llm.sock'
        assert dispatcher.child_socket_path.resolve() == storage / 'llm-child.sock'
        assert os.fstat(descriptor).st_ino == storage.stat().st_ino
        assert storage.stat().st_mode & 0o777 == 0o700
        assert dispatcher.socket_path.stat().st_mode & 0o777 == 0o600
    finally:
        dispatcher.shutdown()
    assert not storage.exists()
    with pytest.raises(OSError) as failure:
        os.fstat(descriptor)
    assert failure.value.errno == errno.EBADF


def test_failed_server_setup_closes_deep_directory_pin(tmp_path, monkeypatch):
    base = tmp_path / ('failed-base-' + 'x' * 100)
    base.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(base))
    descriptor = []
    def refused(self, run_id):
        descriptor.append(int(self.socket_path.parent.name))
        raise OSError('bind refused')
    monkeypatch.setattr(LLMDispatcher, '_init_server', refused)
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {}
    with pytest.raises(OSError, match='bind refused'):
        LLMDispatcher(run_id='failed-owned', creds=creds)
    assert not list(Path(base).iterdir())
    with pytest.raises(OSError) as failure:
        os.fstat(descriptor[0])
    assert failure.value.errno == errno.EBADF
