"""Rootfs archive cleanup preserves quota and extraction operation failures."""
import errno
import io
from types import SimpleNamespace
import tarfile

import pytest

from core.container import export as module
from core.container.tests.test_rootfs_transaction import archive


@pytest.fixture
def resources(tmp_path, monkeypatch):
    path = archive(tmp_path)
    state = SimpleNamespace(path=path, dest=tmp_path / 'rootfs', archives=[], readers=[],
                            wrappers=[], closes=0, extracted=[], primary=None, cleanup=None, skip=False)
    native_open = tarfile.open

    class Reader(io.BufferedReader):
        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    def open_archive(path):
        assert path == state.path
        tf = native_open(path)
        assert tf._extfileobj is False
        state.archives.append(tf)
        state.readers.append(tf.fileobj)
        wrapper = Reader(tf.fileobj)
        state.wrappers.append(wrapper)
        tf.fileobj = wrapper
        native_extract = tf.extract

        def extract(member, *args, **kwargs):
            if state.skip and member.name == 'first':
                raise OSError(errno.ENOENT, 'controlled unsupported member')
            native_extract(member, *args, **kwargs)
            state.extracted.append(member.name)
            if state.primary is not None:
                raise state.primary
        tf.extract = extract
        return tf

    def forbidden(*args, **kwargs):
        pytest.fail('native archive control invoked a container command')

    monkeypatch.setattr(module, 'tarfile', SimpleNamespace(**{**vars(tarfile), 'open': open_archive}))
    monkeypatch.setattr(module, 'run_cli', forbidden)
    try:
        yield state
    finally:
        for wrapper in state.wrappers:
            if not wrapper.closed:
                io.BufferedReader.close(wrapper)
        for tf in state.archives:
            tarfile.TarFile.close(tf)


def assert_retired(state):
    assert state.closes == len(state.readers) == 1
    assert all(reader.closed for reader in state.readers)
    assert all(wrapper.closed for wrapper in state.wrappers)
    assert list(state.dest.parent.glob('raptor-rootfs-*')) == []


def assert_unpublished(state, before):
    if before is None:
        assert not state.dest.exists()
    else:
        assert state.dest.stat().st_ino == before.st_ino
        assert list(state.dest.iterdir()) == []
    assert_retired(state)


@pytest.mark.parametrize('quota', ['entries', 'bytes'])
@pytest.mark.parametrize('existing', [False, True])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_native_quota_refusal_survives_underlying_close(resources, quota, existing, cleanup):
    if existing:
        resources.dest.mkdir()
    before = resources.dest.stat() if existing else None
    resources.cleanup = cleanup('after native TAR input close')
    limits = {'max_entry_count': 1} if quota == 'entries' else {'max_total_bytes': 16}
    with pytest.raises(module.RootfsQuotaExceeded):
        module.extract_rootfs_tar(resources.path, resources.dest, **limits)
    assert resources.extracted == ['first']
    assert_unpublished(resources, before)


@pytest.mark.parametrize('primary', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_extraction_failure_keeps_identity(resources, primary, cleanup):
    resources.primary = primary('after native ordinary member extraction')
    resources.cleanup = cleanup('after native TAR input close')
    with pytest.raises(primary) as caught:
        module.extract_rootfs_tar(resources.path, resources.dest)
    assert caught.value is resources.primary
    assert resources.extracted == ['first']
    assert_unpublished(resources, None)


def test_storage_error_keeps_original_errno(resources):
    resources.primary = OSError(errno.EIO, 'controlled storage error after extraction')
    resources.cleanup = OSError(errno.EBADF, 'after native TAR input close')
    with pytest.raises(OSError) as caught:
        module.extract_rootfs_tar(resources.path, resources.dest)
    assert caught.value is resources.primary and caught.value.errno == errno.EIO
    assert_unpublished(resources, None)


@pytest.mark.parametrize('existing', [False, True])
@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt])
def test_fresh_close_failure_prevents_publication(resources, existing, cleanup):
    if existing:
        resources.dest.mkdir()
    before = resources.dest.stat() if existing else None
    resources.cleanup = cleanup('fresh archive close failure')
    with pytest.raises(cleanup) as caught:
        module.extract_rootfs_tar(resources.path, resources.dest)
    assert caught.value is resources.cleanup
    assert resources.extracted == ['first', 'second']
    assert_unpublished(resources, before)


@pytest.mark.parametrize('existing', [False, True])
def test_healthy_archive_publishes_only_complete_tree(resources, existing):
    if existing:
        resources.dest.mkdir()
    assert module.extract_rootfs_tar(resources.path, resources.dest) == (2, 0)
    assert {p.name: p.read_bytes() for p in resources.dest.iterdir()} == {'first': b'x' * 16, 'second': b'x' * 16}
    assert_retired(resources)


@pytest.mark.parametrize('cleanup', [None, OSError])
def test_handled_member_skip_keeps_fresh_close_policy(resources, cleanup):
    resources.skip = True
    resources.cleanup = cleanup('fresh close after handled skip') if cleanup else None
    if cleanup:
        with pytest.raises(cleanup) as caught:
            module.extract_rootfs_tar(resources.path, resources.dest)
        assert caught.value is resources.cleanup
        assert_unpublished(resources, None)
    else:
        assert module.extract_rootfs_tar(resources.path, resources.dest) == (1, 1)
        assert [p.name for p in resources.dest.iterdir()] == ['second']
        assert_retired(resources)
