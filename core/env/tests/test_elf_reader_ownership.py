"""Executable discovery retires ordinary header readers on every outcome."""
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.env import build


@pytest.fixture
def reader(tmp_path, monkeypatch):
    path = tmp_path / 'app'
    payload = b'\x7fELF' + b'ordinary inert bytes'
    path.write_bytes(payload)
    path.chmod(0o700)
    state = SimpleNamespace(path=path, payload=payload, primary=None, cleanup=None,
                            opened=[], wrappers=[], reads=[], closes=0)

    class Reader(io.BufferedReader):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append(size)
            if state.primary is not None:
                raise state.primary
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    class InputPath(type(Path())):
        def open(self, mode='r', *args, **kwargs):
            assert mode == 'rb' and not args and not kwargs
            native = super().open(mode)
            state.opened.append(native)
            wrapper = Reader(native)
            state.wrappers.append(wrapper)
            return wrapper

    monkeypatch.setattr(build, 'Path', InputPath)
    state.run = lambda: build._elf_executables(tmp_path)
    try:
        yield state
    finally:
        for stream in state.wrappers:
            if not stream.closed:
                io.BufferedReader.close(stream)


def assert_retired(reader):
    assert reader.reads == [4]
    assert reader.closes == len(reader.opened) == 1
    assert all(stream.closed for stream in reader.opened + reader.wrappers)
    assert reader.path.read_bytes() == reader.payload


@pytest.mark.parametrize('primary', [ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_primary_read_failure_survives_consumed_close(reader, primary, cleanup):
    reader.primary = primary('after native header read')
    reader.cleanup = cleanup('after native reader close')
    with pytest.raises(primary) as caught:
        reader.run()
    assert caught.value is reader.primary
    assert_retired(reader)


@pytest.mark.parametrize('cleanup', [None, OSError, KeyboardInterrupt])
def test_handled_read_oserror_keeps_fresh_cleanup_policy(reader, cleanup):
    reader.primary = OSError('after native header read')
    reader.cleanup = cleanup('fresh cleanup failure') if cleanup else None
    if cleanup is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt) as caught:
            reader.run()
        assert caught.value is reader.cleanup
    else:
        assert reader.run() == {}
    assert_retired(reader)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt])
def test_fresh_close_failure_keeps_existing_policy(reader, cleanup):
    reader.cleanup = cleanup('fresh cleanup failure')
    if cleanup is OSError:
        assert reader.run() == {}
    else:
        with pytest.raises(KeyboardInterrupt) as caught:
            reader.run()
        assert caught.value is reader.cleanup
    assert_retired(reader)


def test_native_header_admitted_without_executing_input(reader):
    assert reader.run() == {'app': reader.path}
    assert_retired(reader)


def test_non_elf_skip_keeps_fresh_cleanup_cancellation(reader):
    reader.payload = b'ordinary non executable content'
    reader.path.write_bytes(reader.payload)
    reader.cleanup = KeyboardInterrupt('fresh close after non ELF header')
    with pytest.raises(KeyboardInterrupt) as caught:
        reader.run()
    assert caught.value is reader.cleanup
    assert_retired(reader)
