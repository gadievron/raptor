"""Borrowed EOCD inputs retain primary errors during position restoration."""
import io
import os
from types import SimpleNamespace

import pytest

from core.zip import eocd


@pytest.fixture
def held(tmp_path):
    path = tmp_path / 'held.zip'
    payload = b'PK\x05\x06' + bytes(18)
    path.write_bytes(payload)
    state = SimpleNamespace(primary=None, cleanup=None, reads=[], restores=0, closes=0,
                            armed=False, original=7, path=path, payload=payload)

    class Reader(io.BufferedReader):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append((size, data))
            if state.primary is not None:
                raise state.primary
            return data

        def seek(self, offset, whence=0):
            result = super().seek(offset, whence)
            if state.armed and offset == state.original and whence == 0:
                state.restores += 1
                if state.cleanup is not None:
                    raise state.cleanup
            return result

        def close(self):
            if not self.closed:
                state.closes += 1
            return super().close()

    with path.open('rb') as native:
        stream = Reader(native)
        state.stream, state.native, state.fd = stream, native, native.fileno()
        state.identity = os.fstat(state.fd)
        stream.seek(state.original)
        state.armed = True
        state.run = lambda: eocd.peek_eocd(stream)
        try:
            yield state
        finally:
            state.armed = False
            stream.close()
            assert state.closes == 1 and path.read_bytes() == payload


def restored_and_borrowed(held):
    assert held.reads == [(22, held.payload)] and held.restores == 1
    assert held.stream.tell() == held.original
    assert not held.stream.closed and not held.native.closed and held.closes == 0
    info = os.fstat(held.fd)
    assert (info.st_dev, info.st_ino) == (held.identity.st_dev, held.identity.st_ino)


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_public_borrowed_read_error_survives_actual_restore_failure(held, primary, cleanup):
    held.primary = primary('after native EOCD read')
    held.cleanup = cleanup('after actual native restore')
    with pytest.raises(primary) as caught:
        held.run()
    assert caught.value is held.primary
    restored_and_borrowed(held)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, MemoryError])
def test_public_fresh_restore_failure_remains_visible(held, cleanup):
    held.cleanup = cleanup('fresh position restore failure')
    with pytest.raises(cleanup) as caught:
        held.run()
    assert caught.value is held.cleanup
    restored_and_borrowed(held)


def test_public_handled_read_error_still_returns_unknown(held):
    held.primary = OSError('ordinary native read failure')
    assert held.run() is None
    restored_and_borrowed(held)


def test_public_handled_read_error_does_not_hide_fresh_restore_failure(held):
    held.primary = OSError('ordinary native read failure')
    held.cleanup = MemoryError('fresh restore failure after handled read error')
    with pytest.raises(MemoryError) as caught:
        held.run()
    assert caught.value is held.cleanup
    restored_and_borrowed(held)


def test_public_healthy_borrowed_empty_zip_restores_position(held):
    assert held.run() == eocd.EocdSummary(0, 0)
    restored_and_borrowed(held)
