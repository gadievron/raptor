"""Build teardown finishes later paths and preserves the active operation error."""
import pytest

from core.build import artifacts
from core.build.tests import test_build_artifact_lifecycle as lifecycle


@pytest.fixture
def detector(tmp_path, monkeypatch):
    return lifecycle.detector.__wrapped__(tmp_path, monkeypatch)


def test_interrupted_cleanup_still_reclaims_later_artifacts(tmp_path, monkeypatch):
    blocked = tmp_path / 'blocked'
    blocked.mkdir()
    other = tmp_path / 'other'
    other.write_bytes(b'owned script')
    error = KeyboardInterrupt('owned cleanup interruption')

    def fail(path):
        raise error

    monkeypatch.setattr(artifacts, 'rmtree_hardened', fail)
    pending = [blocked, other]
    with pytest.raises(KeyboardInterrupt) as caught:
        artifacts.cleanup_build_paths(pending)
    assert caught.value is error
    assert not other.exists()
    assert pending == [blocked]


@pytest.mark.parametrize('stage', ['stat', 'unlink', 'rmtree'])
@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('preserve', [False, True])
def test_cleanup_records_failed_paths_and_continues(tmp_path, monkeypatch, stage, error_type, preserve):
    blocked = tmp_path / 'blocked'
    if stage == 'rmtree':
        blocked.mkdir()
    else:
        blocked.write_bytes(b'owned artifact')
    other = tmp_path / 'other'
    other.write_bytes(b'owned script')
    failure = error_type('owned cleanup error')
    armed = [True]

    class Candidate(type(blocked)):
        def lstat(self):
            if armed[0] and stage == 'stat':
                raise failure
            return super().lstat()

        def unlink(self, *args, **kwargs):
            if armed[0] and stage == 'unlink':
                raise failure
            return super().unlink(*args, **kwargs)

    original = artifacts.rmtree_hardened

    def remove(path):
        if armed[0] and path == blocked:
            raise failure
        return original(path)

    monkeypatch.setattr(artifacts, 'rmtree_hardened', remove)
    pending = [Candidate(blocked), other]
    try:
        if preserve:
            artifacts.cleanup_build_paths(pending, preserve_error=True)
        else:
            with pytest.raises(error_type) as caught:
                artifacts.cleanup_build_paths(pending)
            assert caught.value is failure
        assert pending == [blocked]
        assert not other.exists()
    finally:
        armed[0] = False
    artifacts.cleanup_build_paths(pending)
    assert not pending
    assert not blocked.exists()


@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_synthesis_keeps_primary_error_and_reclaims_later_script(detector, tmp_path, monkeypatch, primary_type, cleanup_type):
    primary = primary_type('owned synthesis failure')
    secondary = cleanup_type('owned teardown failure')

    def fail_build(*args, **kwargs):
        raise primary

    def fail_cleanup(path):
        raise secondary

    monkeypatch.setattr(detector, '_dry_run', fail_build)
    with monkeypatch.context() as scope:
        scope.setattr(artifacts, 'rmtree_hardened', fail_cleanup)
        with pytest.raises(primary_type) as caught:
            detector.synthesise_build_command('cpp')
        assert caught.value is primary
        assert not [p for p in tmp_path.glob('.raptor_build_*') if p.is_file()]
    for path in tmp_path.glob('.raptor_build_*'):
        assert artifacts.rmtree_hardened(path)


@pytest.mark.parametrize('first_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_first_cleanup_error_wins_after_every_artifact_is_attempted(tmp_path, monkeypatch, first_type):
    first, second, last = [tmp_path / name for name in ('first', 'second', 'last')]
    first.mkdir()
    second.mkdir()
    last.write_bytes(b'owned script')
    error = first_type('first teardown failure')
    calls = []

    def fail(path):
        calls.append(path)
        if path == first:
            raise error
        raise KeyboardInterrupt('later teardown failure')

    monkeypatch.setattr(artifacts, 'rmtree_hardened', fail)
    pending = [first, second, last]
    with pytest.raises(first_type) as caught:
        artifacts.cleanup_build_paths(pending)
    assert caught.value is error
    assert calls == [first, second]
    assert pending == [first, second]
    assert not last.exists()
