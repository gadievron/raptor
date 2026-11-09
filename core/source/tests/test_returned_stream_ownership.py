"""Returned streams retain ownership through native construction failures."""
import errno
import io
import os
from contextlib import suppress

import pytest

from core.source import beneath, contained, streams
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('route', ['direct', 'beneath', 'walk'])
def test_native_codec_failure_keeps_recycled_descriptor(tmp_path, monkeypatch, route):
    path, sentinel_path = tmp_path / 'input.txt', tmp_path / 'sentinel.txt'
    path.write_text('owned input')
    sentinel_path.write_text('owned sentinel')
    original_adopt, original_factory = os.fdopen, io.open
    original_open, original_close = os.open, os.close
    sentinels = []

    def failed_construction(factory):
        def invoke(*args, **kwargs):
            try:
                return factory(*args, **kwargs)
            except LookupError:
                fd = original_open(sentinel_path, os.O_RDONLY)
                info = os.fstat(fd)
                sentinels.append((fd, (info.st_dev, info.st_ino)))
                raise
        return invoke

    owner = contained if route == 'direct' else beneath
    if route == 'walk':
        monkeypatch.setattr(beneath, '_OPENAT2_ARCH_OK', False)
    patch_module_attribute(monkeypatch, owner, 'os', 'fdopen', failed_construction(original_adopt))
    patch_module_attribute(monkeypatch, streams, 'io', 'open', failed_construction(original_factory))
    try:
        with pytest.raises(LookupError):
            if route == 'direct':
                contained.open_regular(path, 'r', encoding='raptor-no-such-codec')
            else:
                beneath.open_regular_beneath(tmp_path, path.name, 'r', encoding='raptor-no-such-codec')
        assert len(sentinels) == 1
        assert os.read(sentinels[0][0], 32) == b'owned sentinel'
    finally:
        for fd, identity in sentinels:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                original_close(fd)


@pytest.mark.parametrize('transferred', [False, True])
@pytest.mark.parametrize('error_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_factory_failure_consumes_descriptor_once_and_keeps_primary(
    tmp_path, monkeypatch, transferred, error_type,
):
    path, sentinel_path = tmp_path / 'input', tmp_path / 'sentinel'
    path.write_bytes(b'input')
    sentinel_path.write_bytes(b'sentinel')
    original_close, original_open = os.close, os.open
    fd = original_open(path, os.O_RDONLY)
    primary = error_type('construction failed')
    sentinels, closed = [], []

    def close(descriptor):
        original_close(descriptor)
        closed.append(descriptor)
        raise RuntimeError('secondary close failure')

    def factory(name, mode, *, opener, **kwargs):
        if transferred:
            assert opener(name, os.O_RDONLY) == fd
            original_close(fd)
            sentinel = original_open(sentinel_path, os.O_RDONLY)
            assert sentinel == fd
            sentinels.append(sentinel)
        raise primary

    patch_module_attribute(monkeypatch, streams, 'io', 'open', factory)
    try:
        with pytest.raises(error_type) as caught:
            streams.adopt_fd(fd, 'rb', close)
        assert caught.value is primary
        if transferred:
            assert closed == []
            assert os.read(sentinels[0], 16) == b'sentinel'
        else:
            assert closed == [fd]
            with pytest.raises(OSError) as retired:
                os.fstat(fd)
            assert retired.value.errno == errno.EBADF
    finally:
        for sentinel in sentinels:
            with suppress(OSError):
                info = os.fstat(sentinel)
                expected = sentinel_path.stat()
                if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
                    original_close(sentinel)
        if not closed and not sentinels:
            with suppress(OSError):
                original_close(fd)


@pytest.mark.parametrize('mode,kwargs,expected', [
    ('rb', {}, b'caf\xe9\r\n'),
    ('rb', {'buffering': 0}, b'caf\xe9\r\n'),
    ('r', {'encoding': 'latin-1', 'newline': ''}, 'caf\xe9\r\n'),
    ('r', {'encoding': 'utf-8', 'errors': 'replace'}, 'caf\ufffd\n'),
])
def test_success_keeps_native_name_options_and_close_ownership(tmp_path, mode, kwargs, expected):
    path = tmp_path / 'input'
    path.write_bytes(b'caf\xe9\r\n')
    fd = os.open(path, os.O_RDONLY)
    original_info = os.fstat(fd)
    stream = None
    try:
        stream = streams.adopt_fd(fd, mode, **kwargs)
        assert stream.name == fd
        assert stream.fileno() == fd
        with stream:
            assert stream.read() == expected
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
    finally:
        if stream is not None:
            stream.close()
        else:
            with suppress(OSError):
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == (original_info.st_dev, original_info.st_ino):
                    os.close(fd)


def test_explicit_borrowed_close_and_ignored_fd_opener_remain_supported(tmp_path):
    path = tmp_path / 'input'
    path.write_bytes(b'owned')
    calls = []
    fd = os.open(path, os.O_RDONLY)
    original_info = os.fstat(fd)
    try:
        with streams.adopt_fd(fd, 'rb', closefd=False, opener=lambda *args: calls.append(args)) as stream:
            assert stream.name == fd and stream.read() == b'owned'
        assert os.fstat(fd).st_size == 5
        assert calls == []
    finally:
        with suppress(OSError):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (original_info.st_dev, original_info.st_ino):
                os.close(fd)


def test_owning_fd_opener_remains_ignored(tmp_path):
    path = tmp_path / 'input'
    path.write_bytes(b'owned')
    calls = []
    fd = os.open(path, os.O_RDONLY)
    with streams.adopt_fd(fd, 'rb', opener=lambda *args: calls.append(args)) as stream:
        assert stream.read() == b'owned'
    assert calls == []


@pytest.mark.parametrize('route', ['direct', 'beneath', 'walk'])
def test_unknown_constructor_option_releases_descriptor(tmp_path, monkeypatch, route):
    path = tmp_path / 'input'
    path.write_bytes(b'owned')
    owner = contained if route == 'direct' else beneath
    original_open, original_close = os.open, os.close
    descriptors = {}

    def record(fd):
        info = os.fstat(fd)
        descriptors[fd] = (info.st_dev, info.st_ino)

    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        record(fd)
        return fd

    original_adopt = owner.adopt_fd

    def adopt(*args, **kwargs):
        record(args[0])
        return original_adopt(*args, **kwargs)

    if route == 'walk':
        monkeypatch.setattr(beneath, '_OPENAT2_ARCH_OK', False)
    monkeypatch.setattr(owner, 'adopt_fd', adopt)
    patch_module_attribute(monkeypatch, owner, 'os', 'open', opened)
    try:
        with pytest.raises(TypeError):
            if route == 'direct':
                contained.open_regular(path, 'rb', close_fd='unsupported')
            else:
                beneath.open_regular_beneath(tmp_path, path.name, 'rb', close_fd='unsupported')
        assert descriptors
        for fd in descriptors:
            with pytest.raises(OSError) as retired:
                os.fstat(fd)
            assert retired.value.errno == errno.EBADF
    finally:
        for fd, identity in descriptors.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                original_close(fd)
