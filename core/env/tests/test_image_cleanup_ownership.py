"""Cleanup coordination uses owned-file adapters without a container daemon."""
import logging
from types import SimpleNamespace

import pytest

from core.container import lifecycle
from core.env import build


@pytest.fixture
def cleanup(tmp_path, monkeypatch):
    paths = [tmp_path / name for name in ('tagged', 'dangling')]
    for path in paths:
        path.write_bytes(b'inert owned cleanup receipt')
    state = SimpleNamespace(paths=paths, first_error=None, second_error=None,
                            diagnostic_error=None, calls=[], diagnostics=[])
    build_id = 'owned-cleanup-scope'

    def remove(label, value, *, tag_repo=None, tag_value=None):
        assert (label, value, tag_repo, tag_value) == (
            build.BUILD_LABEL, build_id, 'raptor-env-build', build_id)
        paths[0].unlink()
        state.calls.append('tagged')
        if state.first_error is not None:
            raise state.first_error
        return 1

    def prune(label, value):
        assert (label, value) == (build.BUILD_LABEL, build_id)
        paths[1].unlink()
        state.calls.append('dangling')
        if state.second_error is not None:
            raise state.second_error
        return True

    def forbidden(*args, **kwargs):
        pytest.fail('container CLI must not run in owned-file coordination controls')

    monkeypatch.setattr(lifecycle, 'remove_labeled_images', remove)
    monkeypatch.setattr(lifecycle, 'prune_labeled_dangling', prune)
    monkeypatch.setattr(lifecycle, 'run_cli', forbidden)

    class DiagnosticHandler(logging.Handler):
        def emit(self, record):
            state.diagnostics.append(record)
            if state.diagnostic_error is not None:
                raise state.diagnostic_error

    logger = logging.Logger('owned-build-cleanup', level=logging.WARNING)
    logger.propagate = False
    handler = DiagnosticHandler()
    logger.addHandler(handler)
    monkeypatch.setattr(build, 'logger', logger)

    def run(primary):
        with build._image_cleanup(build_id):
            if primary is not None:
                raise primary

    state.run = run
    try:
        yield state
    finally:
        logger.removeHandler(handler)
        handler.close()


def assert_retired(state):
    assert state.calls == ['tagged', 'dangling']
    assert not any(path.exists() for path in state.paths)


@pytest.mark.parametrize('primary_type', [None, OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('diagnostic_type', [MemoryError, KeyboardInterrupt, SystemExit])
def test_diagnostic_refusal_does_not_skip_second_cleanup(cleanup, primary_type, diagnostic_type):
    primary = primary_type('active build error') if primary_type else None
    cleanup.first_error = OSError('after native first cleanup')
    cleanup.diagnostic_error = diagnostic_type('diagnostic refusal')
    expected = primary if primary is not None else cleanup.first_error
    with pytest.raises(type(expected)) as caught:
        cleanup.run(primary)
    assert caught.value is expected
    assert_retired(cleanup)
    assert len(cleanup.diagnostics) == 1
    assert cleanup.diagnostics[0].exc_info[1] is cleanup.first_error
    assert cleanup.diagnostics[0].args == ('owned-cleanup-scope',)


def test_two_fresh_cleanup_errors_keep_first_identity(cleanup):
    cleanup.first_error = OSError('first cleanup')
    cleanup.second_error = ValueError('second cleanup')
    with pytest.raises(OSError) as caught:
        cleanup.run(None)
    assert caught.value is cleanup.first_error
    assert_retired(cleanup)
    assert [r.exc_info[1] for r in cleanup.diagnostics] == [cleanup.first_error, cleanup.second_error]


def test_body_error_survives_two_cleanup_and_diagnostic_errors(cleanup):
    primary = KeyboardInterrupt('active build error')
    cleanup.first_error = OSError('first cleanup')
    cleanup.second_error = SystemExit('second cleanup')
    cleanup.diagnostic_error = MemoryError('diagnostic refusal')
    with pytest.raises(KeyboardInterrupt) as caught:
        cleanup.run(primary)
    assert caught.value is primary
    assert_retired(cleanup)
    assert len(cleanup.diagnostics) == 2


def test_only_second_cleanup_error_is_visible(cleanup):
    cleanup.second_error = SystemExit('second cleanup')
    with pytest.raises(SystemExit) as caught:
        cleanup.run(None)
    assert caught.value is cleanup.second_error
    assert_retired(cleanup)
    assert len(cleanup.diagnostics) == 1


def test_healthy_callbacks_complete_without_diagnostics(cleanup):
    cleanup.run(None)
    assert_retired(cleanup)
    assert cleanup.diagnostics == []


def test_body_error_survives_healthy_cleanup(cleanup):
    primary = ValueError('active build error')
    with pytest.raises(ValueError) as caught:
        cleanup.run(primary)
    assert caught.value is primary
    assert_retired(cleanup)
    assert cleanup.diagnostics == []
