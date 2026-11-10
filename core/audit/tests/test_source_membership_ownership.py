"""Own native saved-source archive reads without invoking CodeQL."""
from collections import OrderedDict
from types import SimpleNamespace
import sys
import zipfile

import pytest

from core.audit import codeql_dbs as module
from core.testing.module_state import isolated_module_state


@pytest.fixture
def archive(tmp_path, monkeypatch):
    path = tmp_path / 'owned-src.zip'
    native_zip = zipfile.ZipFile
    with native_zip(path, 'w') as zf:
        zf.writestr('work/src/owned.c', b'owned inert source')
    state = SimpleNamespace(path=path, opened=[], files=[], reads=0, closes=0,
                            primary=None, cleanup=None, logs=[], log_error=None)

    class Archive(native_zip):
        def namelist(self):
            names = super().namelist()
            state.reads += 1
            if state.primary is not None:
                raise state.primary
            return names

        def close(self):
            if self.fp is None:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    def construct(*args, **kwargs):
        assert args == (path,) and not kwargs
        zf = Archive(*args, **kwargs)
        state.opened.append(zf)
        state.files.append(zf.fp)
        return zf

    def debug(*args, **kwargs):
        info = kwargs.get('exc_info')
        state.logs.append(sys.exc_info() if info is True else info)
        if state.log_error is not None:
            raise state.log_error

    monkeypatch.setattr(zipfile, 'ZipFile', construct)
    monkeypatch.setattr(module, 'logger', SimpleNamespace(debug=debug))
    with isolated_module_state(module, {'_SRC_INDEX_CACHE': OrderedDict()}, lock=module._SRC_INDEX_LOCK):
        try:
            yield state
        finally:
            for zf in state.opened:
                native_zip.close(zf)


def assert_retired(state):
    assert state.reads == state.closes == len(state.opened) == 1
    assert all(stream.closed for stream in state.files)
    assert all(zf.fp is None for zf in state.opened)


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_unhandled_membership_interrupt_survives_native_close(archive, primary, cleanup):
    archive.primary = primary('membership interrupted')
    archive.cleanup = cleanup('after native ZIP close')
    with pytest.raises(primary) as caught:
        module._src_zip_index(archive.path)
    assert caught.value is archive.primary
    assert not module._SRC_INDEX_CACHE and not archive.logs
    assert_retired(archive)


@pytest.mark.parametrize('primary', [RuntimeError, MemoryError])
@pytest.mark.parametrize('cleanup', [None, SystemExit])
def test_handled_read_failure_keeps_fresh_cleanup_policy(archive, primary, cleanup):
    archive.primary = primary('handled metadata error')
    archive.cleanup = cleanup('fresh cleanup cancellation') if cleanup else None
    if cleanup:
        with pytest.raises(cleanup) as caught:
            module._src_zip_index(archive.path)
        assert caught.value is archive.cleanup
        assert not archive.logs
    else:
        assert module._src_zip_index(archive.path) is None
        assert len(archive.logs) == 1 and archive.logs[0][1] is archive.primary
    assert not module._SRC_INDEX_CACHE
    assert_retired(archive)


@pytest.mark.parametrize('cleanup', [OSError, MemoryError, KeyboardInterrupt])
def test_fresh_close_failure_retains_unknown_or_cancellation_policy(archive, cleanup):
    archive.cleanup = cleanup('fresh close failure')
    if cleanup is KeyboardInterrupt:
        with pytest.raises(cleanup) as caught:
            module._src_zip_index(archive.path)
        assert caught.value is archive.cleanup
        assert not archive.logs
    else:
        assert module._src_zip_index(archive.path) is None
        assert len(archive.logs) == 1 and archive.logs[0][1] is archive.cleanup
    assert not module._SRC_INDEX_CACHE
    assert_retired(archive)


def test_logger_failure_propagates_once_after_native_retirement(archive):
    archive.primary = RuntimeError('handled metadata error')
    archive.log_error = LookupError('diagnostic failed')
    with pytest.raises(LookupError) as caught:
        module._src_zip_index(archive.path)
    assert caught.value is archive.log_error
    assert len(archive.logs) == 1 and archive.logs[0][1] is archive.primary
    assert not module._SRC_INDEX_CACHE
    assert_retired(archive)


def test_healthy_native_index_is_cached_without_reopening(archive):
    first = module._src_zip_index(archive.path)
    assert first == {'owned.c': ('work/src/owned.c',)}
    assert module._src_zip_index(archive.path) is first
    assert len(module._SRC_INDEX_CACHE) == 1 and not archive.logs
    assert_retired(archive)
