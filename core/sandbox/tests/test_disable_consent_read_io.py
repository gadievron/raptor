"""Consent validation refuses unsafe objects and bounds actual read bytes."""
import errno
import os
from pathlib import Path
import signal
import subprocess
import sys
from types import ModuleType

import pytest

from core.sandbox import disable_consent as dc
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def consent(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    private = ModuleType('consent_read_os')
    vars(private).update(vars(os))
    monkeypatch.setattr(dc, 'os', private)
    nonce = dc._mint_nonce(tmp_path)
    return tmp_path / dc._nonce_filename(nonce), nonce


@pytest.mark.parametrize('chunk_size', [1, 7, 32])
def test_short_reads_are_accumulated(consent, monkeypatch, chunk_size):
    path, nonce = consent
    real_read = os.read
    monkeypatch.setattr(dc.os, 'read', lambda fd, count: real_read(fd, min(count, chunk_size)))
    assert dc._nonce_file_consents(path, nonce) is True


def test_growth_past_limit_is_refused(consent, monkeypatch):
    path, nonce = consent
    path.write_bytes((dc._nonce_digest(nonce) + '\n').encode()
                     + b' ' * dc.NONCE_FILE_MAX_BYTES)
    real_fstat = os.fstat

    def stale_size(fd):
        st = real_fstat(fd)
        fields = list(st)
        fields[6] = 65
        return os.stat_result(fields)

    monkeypatch.setattr(dc.os, 'fstat', stale_size)
    assert dc._nonce_file_consents(path, nonce) is False
    assert os.fstat is real_fstat
    with path.open('rb') as native:
        assert os.fstat(native.fileno()).st_size == path.stat().st_size


def test_exact_limit_content_remains_valid(consent):
    path, nonce = consent
    content = dc._nonce_digest(nonce).encode()
    path.write_bytes(content + b' ' * (dc.NONCE_FILE_MAX_BYTES - len(content)))
    assert dc._nonce_file_consents(path, nonce) is True


def test_read_failure_refuses_and_closes(consent, monkeypatch):
    path, nonce = consent
    real_close = os.close
    closed = []

    def fail(fd, count):
        raise OSError(errno.EIO, 'read failed')

    def close(fd):
        closed.append(fd)
        real_close(fd)

    with monkeypatch.context() as scoped:
        scoped.setattr(dc.os, 'read', fail)
        scoped.setattr(dc.os, 'close', close)
        assert dc._nonce_file_consents(path, nonce) is False
    assert len(closed) == 1


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='requires FIFO support')
def test_fifo_without_writer_is_refused_without_blocking(tmp_path):
    path = tmp_path / 'fifo'
    os.mkfifo(path, 0o600)
    program = '''
import importlib.util, signal, sys
import core.sandbox
spec = importlib.util.spec_from_file_location('core.sandbox.consent_reader', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
signal.alarm(3)
assert module._nonce_file_consents(__import__('pathlib').Path(sys.argv[2]), '0' * 32) is False
signal.alarm(0)
'''
    result = subprocess.run([sys.executable, '-c', program, str(Path(dc.__file__)), str(path)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode != -signal.SIGALRM, 'consent read blocked on FIFO'
    assert result.returncode == 0, result.stderr
