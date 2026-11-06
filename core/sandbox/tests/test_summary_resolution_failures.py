"""Best-effort summary state survives Python 3.12 path-resolution failures."""

from pathlib import Path

import pytest

from core.sandbox import summary
from core.testing.sandbox_state_scope import SUMMARY_REGISTRIES, isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


CASES = [
    (summary._record_evidence_write_failure, {}, None),
    (summary.record_proxy_persist_state, {'expected_count': 1, 'flags': ['owned']}, None),
    (summary.get_proxy_persist_state, {}, None),
    (summary.get_evidence_write_failure, {}, False),
    (summary.get_evidence_inode_mismatch, {}, False),
    (summary.record_run_posture, {'mount_ns_active': False, 'restrict_reads': False}, None),
    (summary.get_run_posture, {}, None),
    (summary.record_cli_disable, {'consent': 'owned'}, None),
    (summary.get_cli_disable, {}, None),
    (summary.record_floor_refusal, {'floor': 'full', 'achievable': 'none', 'reason': 'owned'}, None),
    (summary.record_audit_degraded, {'reason': 'owned'}, None),
    (summary.get_audit_degraded, {}, None),
    (summary.reassert_audit_degraded, {}, False),
]


@pytest.fixture
def owned(tmp_path):
    with isolated_sandbox_state(()), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / 'state')
        patch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        yield tmp_path


@pytest.fixture
def monkeypatch(owned):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def failing_path(monkeypatch, error):
    """Patch only summary's native Path subclass, never pathlib globally.

    Python <3.13 raises RuntimeError for resolve() symlink loops even with
    strict=False; see https://docs.python.org/3/library/pathlib.html#pathlib.Path.resolve.
    OSError exercises the existing fallback on newer interpreters too.
    """
    calls = []

    class ResolutionFailure(type(Path())):
        def resolve(self, strict=False):
            calls.append(self)
            raise error

    monkeypatch.setattr(summary, 'Path', ResolutionFailure)
    return ResolutionFailure, calls


@pytest.mark.parametrize('function,kwargs,expected', CASES, ids=[c[0].__name__ for c in CASES])
@pytest.mark.parametrize('error_type', [OSError, RuntimeError])
def test_resolution_failure_preserves_existing_state(owned, monkeypatch, function, kwargs, expected, error_type):
    registries = {name: getattr(summary, name) for name in SUMMARY_REGISTRIES}
    for registry in registries.values():
        registry['owned-existing-run'] = {'sentinel': True}
    before = {name: value.copy() for name, value in registries.items()}
    error = error_type('owned resolution failure')
    path_type, calls = failing_path(monkeypatch, error)
    assert function(path_type(owned / 'unresolvable'), **kwargs) is expected
    assert len(calls) == 1
    for name, registry in registries.items():
        assert getattr(summary, name) is registry
        assert registry == before[name]
    assert not (owned / 'unresolvable').exists()


@pytest.mark.parametrize('function,kwargs,expected', CASES, ids=[c[0].__name__ for c in CASES])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_resolution_cancellation_propagates(owned, monkeypatch, function, kwargs, expected, error_type):
    error = error_type('owned cancellation')
    path_type, calls = failing_path(monkeypatch, error)
    with pytest.raises(error_type) as caught:
        function(path_type(owned / 'cancelled'), **kwargs)
    assert caught.value is error
    assert len(calls) == 1
    assert all(not getattr(summary, name) for name in SUMMARY_REGISTRIES)
    assert not (owned / 'cancelled').exists()


def test_healthy_state_round_trip_and_snapshot_isolation(owned):
    run = owned / 'run'
    run.mkdir()
    summary.record_proxy_persist_state(run, expected_count=2, flags=['owned'])
    snapshot = summary.get_proxy_persist_state(run)
    assert snapshot['expected_count'] == 2
    snapshot['flags'].append('caller-edit')
    assert summary.get_proxy_persist_state(run)['flags'] == ['owned']
    summary.record_run_posture(run, mount_ns_active=True, restrict_reads=True)
    posture = summary.get_run_posture(run)
    assert posture is not None
    posture.clear()
    assert summary.get_run_posture(run)
    summary.record_cli_disable(run, consent='owned')
    assert summary.get_cli_disable(run) == 'owned'
    summary._record_evidence_write_failure(run)
    assert summary.get_evidence_write_failure(run) is True
    assert summary.get_evidence_inode_mismatch(run) is False
    summary.record_audit_degraded(run, reason='owned')
    marker = summary.get_audit_degraded(run)
    assert marker['reason'] == 'owned'
    marker.clear()
    assert summary.get_audit_degraded(run)['reason'] == 'owned'
    assert summary.reassert_audit_degraded(run) is False
