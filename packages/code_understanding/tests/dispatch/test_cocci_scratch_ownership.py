"""Retire owned native scratch without generating or executing a rule."""
from types import SimpleNamespace

import pytest

from core.run import scratch
from packages.coccinelle.models import SpatchResult
from packages.code_understanding.dispatch import hunt_cocci_dispatch as dispatch


@pytest.fixture
def resources(tmp_path, monkeypatch):
    repo, parent = tmp_path / 'source', tmp_path / 'scratch-parent'
    repo.mkdir()
    parent.mkdir()
    (repo / 'owned.c').write_text('int owned(void) { return 0; }')
    state = SimpleNamespace(repo=repo, parent=parent, paths=[], rules=[], removed=[],
                            phase='tool', primary=None, cleanup=None, calls=0)
    native_scratch, native_remove, native_write = scratch.scratch_dir, scratch.rmtree_hardened, scratch.write_temp_text

    def allocate(prefix):
        context = native_scratch(prefix, dir=parent, keepalive=False)
        class OwnedContext:
            def __enter__(self):
                path = context.__enter__()
                state.paths.append(path)
                (path / 'ordinary-resource').write_bytes(b'owned')
                return path

            def __exit__(self, *args):
                return context.__exit__(*args)
        return OwnedContext()

    def remove(path):
        assert path in state.paths
        result = native_remove(path)
        state.removed.append(path)
        assert not path.exists()
        if state.cleanup is not None:
            raise state.cleanup
        return result

    def write(text, **kwargs):
        path = native_write(text, **kwargs, dir=parent)
        state.rules.append(path)
        return path

    def forbidden(*args, **kwargs):
        pytest.fail('cleanup control invoked provider or external runner')

    def build(*args):
        if state.phase == 'setup' and state.primary is not None:
            raise state.primary
        return forbidden

    def tool(**kwargs):
        state.calls += 1
        assert kwargs['rule'] in state.rules
        assert kwargs['subprocess_runner'] is forbidden
        if state.phase == 'tool' and state.primary is not None:
            raise state.primary
        return SpatchResult(rule='owned-fixture')

    monkeypatch.setattr(dispatch, 'spatch_is_available', lambda: True)
    monkeypatch.setattr(dispatch, 'translate_pattern_to_cocci_rule', lambda *a, **k: '// owned fixture')
    monkeypatch.setattr(dispatch, 'create_provider', forbidden)
    monkeypatch.setattr(dispatch, '_make_locked_sandbox_runner', build)
    monkeypatch.setattr(dispatch, 'spatch_run_rule', tool)
    monkeypatch.setattr(dispatch, 'scratch_dir', allocate)
    monkeypatch.setattr(scratch, 'write_temp_text', write)
    monkeypatch.setattr(scratch, 'rmtree_hardened', remove)
    state.run = lambda: dispatch.cocci_hunt_dispatch(None, 'owned cleanup control', str(repo))
    try:
        yield state
    finally:
        for path in state.rules:
            path.unlink(missing_ok=True)
        for path in state.paths:
            if path.exists():
                native_remove(path)


def assert_retired(state):
    assert len(state.paths) == len(state.removed) == 1
    assert state.paths == state.removed
    assert all(not path.exists() for path in state.paths + state.rules)


@pytest.mark.parametrize('phase', ['setup', 'tool'])
@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup', [KeyboardInterrupt, SystemExit])
def test_unhandled_interrupt_survives_native_cleanup(resources, phase, primary, cleanup):
    resources.phase = phase
    resources.primary = primary('operation interrupt')
    resources.cleanup = cleanup('after native scratch removal')
    with pytest.raises(primary) as caught:
        resources.run()
    assert caught.value is resources.primary
    assert_retired(resources)


@pytest.mark.parametrize('phase', ['setup', 'tool'])
@pytest.mark.parametrize('primary', [RuntimeError, OSError])
@pytest.mark.parametrize('cleanup', [None, SystemExit])
def test_handled_failure_retains_variant_and_fresh_cleanup_policy(resources, phase, primary, cleanup):
    resources.phase = phase
    resources.primary = primary('handled operation failure')
    resources.cleanup = cleanup('fresh cleanup interrupt') if cleanup else None
    if cleanup:
        with pytest.raises(cleanup) as caught:
            resources.run()
        assert caught.value is resources.cleanup
    else:
        result = resources.run()
        assert len(result) == 1 and 'error' in result[0]
        assert 'handled operation failure' in result[0]['error']
    assert_retired(resources)


@pytest.mark.parametrize('cleanup', [None, KeyboardInterrupt, SystemExit])
def test_success_and_fresh_cleanup_cancellation(resources, cleanup):
    resources.cleanup = cleanup('fresh cleanup interrupt') if cleanup else None
    if cleanup:
        with pytest.raises(cleanup) as caught:
            resources.run()
        assert caught.value is resources.cleanup
    else:
        assert resources.run() == []
    assert resources.calls == 1
    assert_retired(resources)
