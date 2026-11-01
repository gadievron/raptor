"""Portable allocation-policy checks; these do not emulate macOS peer credentials."""
import os
from pathlib import Path
import platform
import tempfile

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher import server


def test_compact_socket_uses_captured_service_base_not_later_environment(monkeypatch):
    # Keep physical test paths short on the real host. Darwin's real private
    # directory remains the backing location when this test runs on macOS.
    base = os.confstr(65537) if platform.system() == 'Darwin' else '/tmp'
    with tempfile.TemporaryDirectory(prefix='rs-', dir=base) as directory:
        selected = Path(directory)
        deep = selected / ('session-' + 'x' * 110)
        deep.mkdir()
        monkeypatch.setattr(tempfile, 'tempdir', str(deep))
        monkeypatch.setattr(server, '_SERVICE_TMP_BASE', str(selected))
        monkeypatch.setenv('_RAPTOR_SERVICE_TMP_BASE', '/changed-after-startup')
        monkeypatch.setattr(server.sys, 'platform', 'darwin')
        creds = CredentialStore.__new__(CredentialStore)
        creds._keys = {}
        dispatcher = server.LLMDispatcher(run_id='compact-service-base', creds=creds)
        try:
            assert dispatcher._sock_dir.parent == selected
            assert dispatcher._sock_dir.name.startswith('rll-')
            assert dispatcher.socket_path.exists()
            assert dispatcher.child_socket_path.exists()
            assert len(os.fsencode(dispatcher.child_socket_path)) <= 100
        finally:
            dispatcher.shutdown()
        assert not list(deep.iterdir())
