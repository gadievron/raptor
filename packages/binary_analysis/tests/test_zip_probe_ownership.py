"""Own native ZIP metadata probes without executing archive contents."""
from types import SimpleNamespace
import zipfile

import pytest

from packages.binary_analysis import manifest
from packages.fuzzing import target_detector


@pytest.fixture(params=['manifest', 'detector'])
def archive(request, tmp_path, monkeypatch):
    path = tmp_path / 'owned.jar'
    names = {'META-INF/MANIFEST.MF', 'Owned.class'}
    with zipfile.ZipFile(path, 'w') as zf:
        for name in names:
            zf.writestr(name, b'owned inert metadata')
    state = SimpleNamespace(path=path, names=names, reader=request.param, opened=[], files=[],
                            closes=0, reads=0, primary=None, cleanup=None, before=path.read_bytes())

    class Archive(zipfile.ZipFile):
        def namelist(self):
            values = super().namelist()
            state.reads += 1
            if state.primary is not None:
                raise state.primary
            return values

        def infolist(self):
            values = super().infolist()
            state.reads += 1
            if state.primary is not None:
                raise state.primary
            return values

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

    module = manifest if request.param == 'manifest' else target_detector
    monkeypatch.setattr(module, 'zipfile', SimpleNamespace(**{**vars(zipfile), 'ZipFile': construct}))
    state.run = lambda: module._zip_members(path) if request.param == 'manifest' else module._detect_zip_artifact(path)
    try:
        yield state
    finally:
        for zf in state.opened:
            zipfile.ZipFile.close(zf)


def assert_retired(state):
    assert state.reads == state.closes == len(state.opened) == 1
    assert all(stream.closed for stream in state.files)
    assert all(zf.fp is None for zf in state.opened)
    assert state.path.read_bytes() == state.before


def assert_refused(state, result):
    if state.reader == 'manifest':
        assert result == set()
    else:
        assert result is None


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup', [OSError, SystemExit])
def test_unhandled_metadata_interrupt_survives_native_close(archive, primary, cleanup):
    archive.primary = primary('metadata operation interrupted')
    archive.cleanup = cleanup('after native ZIP close')
    with pytest.raises(primary) as caught:
        archive.run()
    assert caught.value is archive.primary
    assert_retired(archive)


@pytest.mark.parametrize('primary', [OSError, zipfile.BadZipFile, RuntimeError])
@pytest.mark.parametrize('cleanup', [None, KeyboardInterrupt])
def test_handled_metadata_error_retains_fresh_cleanup_policy(archive, primary, cleanup):
    archive.primary = primary('handled metadata failure')
    archive.cleanup = cleanup('fresh cleanup cancellation') if cleanup else None
    if cleanup:
        with pytest.raises(cleanup) as caught:
            archive.run()
        assert caught.value is archive.cleanup
    else:
        assert_refused(archive, archive.run())
    assert_retired(archive)


@pytest.mark.parametrize('cleanup', [OSError, MemoryError, KeyboardInterrupt])
def test_fresh_close_failure_keeps_existing_policy(archive, cleanup):
    archive.cleanup = cleanup('fresh close failure')
    if cleanup is OSError:
        assert_refused(archive, archive.run())
    else:
        with pytest.raises(cleanup) as caught:
            archive.run()
        assert caught.value is archive.cleanup
    assert_retired(archive)


def test_healthy_native_metadata_stays_admitted(archive):
    result = archive.run()
    if archive.reader == 'manifest':
        assert result == archive.names
    else:
        assert result.kind == 'java-archive'
        assert result.can_fuzz_here is False
    assert_retired(archive)
