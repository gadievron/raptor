"""Absolute deadline accounting using inert adapters and a controlled clock."""
from __future__ import annotations

import contextvars
import subprocess
from types import SimpleNamespace

import pytest

from core.audit.dark_verify import DarkVerifyResult, DarkWitnessSpec
from core.audit.dark_verify import _execute as ex
from core.sandbox.errors import SandboxFloorError
from core.sandbox.tiers import ContainmentTier


@pytest.fixture
def op(tmp_path, monkeypatch):
    (tmp_path / 'a.py').write_text('def f(): return 1\n')
    clock = [100.0]
    calls = []
    monkeypatch.setattr(ex, 'time', SimpleNamespace(monotonic=lambda: clock[0]))

    def backend(cmd, **kwargs):
        calls.append(kwargs['timeout'])
        return subprocess.CompletedProcess(cmd, 0, '', '')

    def stage(timeout):
        return ex._sandbox_run_capped(backend, ['inert'], cap_dir=tmp_path, timeout=timeout)

    return SimpleNamespace(root=tmp_path, clock=clock, calls=calls, stage=stage,
                           spec=DarkWitnessSpec('a:f', 'a.py', 'f', 'python'))


def install(op, monkeypatch, body):
    def executor(spec, root, timeout):
        body(timeout)
        return DarkVerifyResult(spec.finding_key, 'inconclusive')
    monkeypatch.setitem(ex._EXECUTORS, 'python', executor)


def test_remaining_allowance(op, monkeypatch):
    def body(timeout):
        op.clock[0] = 108.0
        op.stage(30)
        op.clock[0] = 109.0
        op.stage(timeout)
    install(op, monkeypatch, body)
    ex.execute_witness(op.spec, op.root, deadline_monotonic=110.0)
    assert op.calls == [2.0, 1.0]


def test_no_deadline_preserves_caps(op, monkeypatch):
    def body(timeout):
        op.clock[0] = 10000.0
        op.stage(30)
        op.stage(timeout)
    install(op, monkeypatch, body)
    ex.execute_witness(op.spec, op.root)
    assert op.calls == [30, 10]


@pytest.mark.parametrize('expiry', [99.0, 100.0])
def test_expired_entry_never_dispatches(op, monkeypatch, expiry):
    def forbidden(*args):
        pytest.fail('expired operation dispatched')
    monkeypatch.setattr(ex, 'validate_spec', forbidden)
    monkeypatch.setitem(ex._EXECUTORS, 'python', forbidden)
    result = ex.execute_witness(op.spec, op.root, deadline_monotonic=expiry)
    assert result.verdict == 'inconclusive'
    assert result.oracle_reliability == 'unavailable'
    assert result.observed_status == ''
    assert not result.violation_observed
    assert 'processing timeout' in result.match_detail
    assert not op.calls


def test_preparation_expiry_blocks_next_stage(op, monkeypatch):
    def prepare(*args):
        op.clock[0] = 110.0
        return ''
    monkeypatch.setattr(ex, 'validate_spec', prepare)
    install(op, monkeypatch, op.stage)
    result = ex.execute_witness(op.spec, op.root, deadline_monotonic=110.0)
    assert result.verdict == 'inconclusive'
    assert not op.calls


def test_completed_observation_survives_late_cleanup(op, monkeypatch):
    observed = DarkVerifyResult('a:f', 'confirmed', observed_status='returned')
    def executor(spec, root, timeout):
        op.stage(timeout)
        op.clock[0] = 120.0
        return observed
    monkeypatch.setitem(ex._EXECUTORS, 'python', executor)
    assert ex.execute_witness(op.spec, op.root, deadline_monotonic=110.0) is observed
    assert op.calls == [10]


@pytest.mark.parametrize('exc', [KeyboardInterrupt(), SandboxFloorError('floor', 'remedy', achievable=ContainmentTier.LANDLOCK_ONLY, floor=ContainmentTier.MOUNT_NS)])
def test_original_floor_and_cancel_propagate_and_context_resets(op, monkeypatch, exc):
    def body(timeout):
        raise exc
    install(op, monkeypatch, body)
    with pytest.raises(type(exc)) as caught:
        ex.execute_witness(op.spec, op.root, deadline_monotonic=110.0)
    assert caught.value is exc
    op.clock[0] = 120.0
    op.stage(30)
    assert op.calls == [30]


def test_nested_deadline_cannot_extend_and_contexts_are_isolated(op, monkeypatch):
    nested = False
    other = contextvars.Context()
    def executor(spec, root, timeout):
        nonlocal nested
        if not nested:
            nested = True
            op.clock[0] = 108.0
            return ex.execute_witness(spec, root, deadline_monotonic=200.0)
        other.run(op.stage, 30)
        op.stage(30)
        return DarkVerifyResult(spec.finding_key, 'inconclusive')
    monkeypatch.setitem(ex._EXECUTORS, 'python', executor)
    ex.execute_witness(op.spec, op.root, deadline_monotonic=110.0)
    op.stage(30)
    assert op.calls == [30, 2.0, 30]


@pytest.mark.parametrize('deadline', [None, 200.0, 105.0])
def test_inflight_timeout_only_maps_shortened_deadline(op, monkeypatch, deadline):
    def backend(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs['timeout'])
    def body(timeout):
        ex._sandbox_run_capped(backend, ['inert'], cap_dir=op.root, timeout=10)
    install(op, monkeypatch, body)
    if deadline == 105.0:
        result = ex.execute_witness(op.spec, op.root, deadline_monotonic=deadline)
        assert result.verdict == 'inconclusive'
        assert result.oracle_reliability == 'unavailable'
        assert 'processing timeout' in result.match_detail
    else:
        with pytest.raises(subprocess.TimeoutExpired):
            ex.execute_witness(op.spec, op.root, deadline_monotonic=deadline)


@pytest.mark.parametrize('mode', ['remaining', 'expired', 'environment_expired', 'timeout'])
def test_rust_preparation_deadline_is_not_tool_absence(op, monkeypatch, mode):
    from core.config import RaptorConfig
    seen = []
    monkeypatch.setattr(ex.shutil, 'which', lambda name: '/owned/rustc')
    def environment():
        if mode == 'environment_expired':
            op.clock[0] = 110.0
        return {}
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', staticmethod(environment))
    def probe(cmd, **kwargs):
        seen.append(kwargs['timeout'])
        if mode == 'timeout':
            raise subprocess.TimeoutExpired(cmd, kwargs['timeout'])
        return subprocess.CompletedProcess(cmd, 1, '', '')
    monkeypatch.setattr(ex, 'subprocess', SimpleNamespace(
        run=probe, SubprocessError=subprocess.SubprocessError,
        TimeoutExpired=subprocess.TimeoutExpired,
    ))
    def body(timeout):
        op.clock[0] = 110.0 if mode == 'expired' else 108.0
        assert ex._resolve_rustc() == '/owned/rustc'
    install(op, monkeypatch, body)
    result = ex.execute_witness(op.spec, op.root, deadline_monotonic=110.0)
    if mode == 'remaining':
        assert seen == [2.0]
        assert 'processing timeout' not in result.match_detail
    else:
        assert seen == ([2.0] if mode == 'timeout' else [])
        assert result.verdict == 'inconclusive'
        assert result.oracle_reliability == 'unavailable'
        assert 'processing timeout' in result.match_detail
