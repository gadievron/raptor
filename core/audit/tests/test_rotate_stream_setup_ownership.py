"""Rotation stream setup cannot retry a consumed descriptor."""
import io
import os
from types import FunctionType, SimpleNamespace

import pytest

from core.audit import audit_log_rotate as rotation
from core.audit import record
from core.source import streams


@pytest.mark.parametrize('mode', ['wb', 'rb'])
@pytest.mark.parametrize('error_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_native_setup_consumption_preserves_foreign_descriptor(tmp_path, monkeypatch, mode, error_type):
    source = tmp_path / record.AUDIT_LOG_FILENAME
    with source.open('wb') as stream:
        stream.truncate(rotation._AUDIT_LOG_MAX_BYTES + 1)
    before = source.stat()
    guard_path = tmp_path / 'owned-guard'
    guard_path.write_bytes(b'rotation owned guard')
    guard = os.open(guard_path, os.O_RDONLY)
    live = {guard}
    consumed = []
    retried = []
    primary = error_type('native rotation setup consumed')

    def fail_after_native(stream):
        fd = stream.fileno()
        stream.close()
        os.dup2(guard, fd)
        live.add(fd)
        consumed.append(fd)
        raise primary

    def fdopen(fd, requested_mode, **kwargs):
        stream = os.fdopen(fd, requested_mode, **kwargs)
        return fail_after_native(stream) if requested_mode == mode else stream

    def native_open(path, requested_mode, **kwargs):
        stream = io.open(path, requested_mode, **kwargs)
        return fail_after_native(stream) if requested_mode == mode else stream

    def close(fd):
        if fd in consumed:
            retried.append(fd)
            live.discard(fd)
        os.close(fd)

    private_os = SimpleNamespace(**{**vars(os), 'fdopen': fdopen, 'close': close})
    monkeypatch.setattr(rotation, 'os', private_os)
    # Isolate the real helper's native constructor seam without changing
    # shared stdlib/module bindings used by other consumers or workers.
    if hasattr(rotation, 'adopt_fd'):
        bindings = dict(streams.adopt_fd.__globals__)
        bindings['io'] = SimpleNamespace(**{**vars(io), 'open': native_open})
        bindings['os'] = private_os
        adopt = FunctionType(streams.adopt_fd.__code__, bindings,
                             streams.adopt_fd.__name__, streams.adopt_fd.__defaults__)
        adopt.__kwdefaults__ = streams.adopt_fd.__kwdefaults__
        monkeypatch.setattr(rotation, 'adopt_fd', adopt)
    try:
        with pytest.raises(error_type) as raised:
            rotation.rotate_audit_log(tmp_path)
        assert raised.value is primary
        assert len(consumed) == 1
        assert not retried
        fd = consumed[0]
        actual, owned = os.fstat(fd), os.fstat(guard)
        assert (actual.st_dev, actual.st_ino) == (owned.st_dev, owned.st_ino)
        assert os.pread(fd, 64, 0) == b'rotation owned guard'
        after = source.stat()
        assert (after.st_ino, after.st_size, after.st_mtime_ns) == (
            before.st_ino, before.st_size, before.st_mtime_ns)
        assert not list(tmp_path.glob(rotation._TMP_PREFIX + '*'))
        assert not list(tmp_path.glob('*.pre-rotate*'))
    finally:
        for fd in live:
            os.close(fd)
