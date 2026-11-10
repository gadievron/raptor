"""Source owns both the native ZIP reader and its borrowed input stream."""
from contextlib import contextmanager
from types import SimpleNamespace
import zipfile

import pytest

from packages.sca.sbom_inventory import source as module


@pytest.fixture
def resources(tmp_path, monkeypatch):
    path = tmp_path / 'owned.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('owned.json', b'{}')
    state = SimpleNamespace(path=path, archives=[], streams=[], closed=[], errors={})
    native_gated = module.open_regular_gated
    native_zip = zipfile.ZipFile

    @contextmanager
    def gated(path):
        stream = None
        try:
            with native_gated(path) as stream:
                state.streams.append(stream)
                yield stream
        finally:
            if stream is not None:
                assert stream.closed
                state.closed.append('stream')
                if 'stream' in state.errors:
                    raise state.errors['stream']

    class Archive(native_zip):
        def close(self):
            if self.fp is None:
                return super().close()
            super().close()
            state.closed.append('archive')
            if 'archive' in state.errors:
                raise state.errors['archive']

    def open_zip(stream):
        assert stream is state.streams[-1]
        archive = Archive(stream)
        state.archives.append(archive)
        return archive

    monkeypatch.setattr(module, 'open_regular_gated', gated)
    monkeypatch.setattr(module, 'zipfile', SimpleNamespace(**{**vars(zipfile), 'ZipFile': open_zip}))
    try:
        yield state
    finally:
        for archive in state.archives:
            native_zip.close(archive)
        for stream in state.streams:
            if not stream.closed:
                stream.close()


def fail_closes(state, role, kind=OSError):
    for name in (['archive', 'stream'] if role == 'both' else [role]):
        state.errors[name] = kind('after native close: ' + name)


def assert_retired(state, archive=True):
    assert len(state.streams) == 1 and state.streams[0].closed
    assert all(item.fp is None for item in state.archives)
    assert state.closed == (['archive', 'stream'] if archive else ['stream'])
    assert len(state.archives) == int(archive)


@pytest.mark.parametrize('role', ['archive', 'stream', 'both'])
def test_duplicate_entry_refusal_survives_consumed_cleanup(resources, role):
    with zipfile.ZipFile(resources.path, 'w') as archive:
        archive.writestr('same.json', b'{}')
        with pytest.warns(UserWarning, match='Duplicate name'):
            archive.writestr('same.json', b'{}')
    fail_closes(resources, role)
    with pytest.raises(ValueError, match='duplicate or excessive ZIP entries'):
        with module.Source(resources.path):
            pytest.fail('duplicate ZIP was admitted')
    assert_retired(resources)


@pytest.mark.parametrize('role', ['archive', 'stream', 'both'])
@pytest.mark.parametrize('primary', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_body_error_keeps_identity_after_native_retirement(resources, role, primary):
    error = primary('owned source operation failed')
    fail_closes(resources, role, MemoryError)
    with pytest.raises(primary) as caught:
        with module.Source(resources.path) as source:
            assert source.contains('owned.json')
            raise error
    assert caught.value is error
    assert_retired(resources)


@pytest.mark.parametrize('role', ['archive', 'stream'])
@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt])
def test_fresh_close_failure_remains_visible(resources, role, cleanup):
    fail_closes(resources, role, cleanup)
    with pytest.raises(cleanup) as caught:
        with module.Source(resources.path) as source:
            assert source.contains('owned.json')
    assert caught.value is resources.errors[role]
    assert_retired(resources)


def test_two_fresh_close_errors_keep_stream_error_precedence(resources):
    resources.errors = {'archive': OSError('ZIP close'), 'stream': LookupError('stream close')}
    with pytest.raises(LookupError) as caught:
        with module.Source(resources.path):
            pass
    assert caught.value is resources.errors['stream']
    assert_retired(resources)


def test_healthy_zip_keeps_borrowed_stream_until_context_exit(resources):
    with module.Source(resources.path) as source:
        assert source.contains('owned.json') and not source.contains('absent.json')
        assert source.archive.fp is resources.streams[0]
        assert not resources.streams[0].closed
    assert_retired(resources)


def test_native_preflight_refusal_retires_only_entered_stream(resources):
    resources.path.write_bytes(b'not a ZIP')
    fail_closes(resources, 'stream')
    with pytest.raises(ValueError, match='invalid or oversized evidence ZIP directory'):
        with module.Source(resources.path):
            pytest.fail('invalid ZIP was admitted')
    assert_retired(resources, archive=False)
