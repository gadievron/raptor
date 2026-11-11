"""Retain witness observations before publishing stronger assessments."""

import errno
import json

import pytest

from core.audit import orchestrator as orch
from core.audit import dark_verify
from core.audit.tests import test_dark_verify_parallel as harness
from core.audit.tests.test_dark_verify_parallel import _config, _outcome, _result, _run, _snapshot


def test_dark_promotion_requires_retained_authoritative_observation(tmp_path, monkeypatch):
    cfg = _config(tmp_path)
    result = _result([_outcome(0)])
    before = _snapshot(result)
    executions = []
    writes = []
    failure = OSError(errno.EIO, 'owned authoritative-result persistence fault')

    def nonexecuting_adapter(spec, target_root, **kwargs):
        executions.append(spec.finding_key)
        return dark_verify.DarkVerifyResult(
            finding_key=spec.finding_key, verdict='confirmed',
            match_detail='nonexecuting typed adapter fixture',
            violation_observed=True, oracle_reliability='decisive',
        )

    real_save = orch.save_json

    def reject_authoritative_write(path, data, *args, **kwargs):
        if path.name == 'dark-verify-results.json':
            writes.append((result.outcomes[0].status, result.findings))
            raise failure
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(dark_verify, 'execute_witness', nonexecuting_adapter)
    monkeypatch.setattr(orch, 'save_json', reject_authoritative_write)
    with pytest.raises(OSError) as caught:
        _run(result, cfg, workers=1)
    assert caught.value is failure
    assert executions == ['m0.py:f0']
    assert len(writes) == 1
    assert not (cfg.out_dir / 'dark-verify-results.json').exists()
    assert _snapshot(result) == before, (
        'stronger assessment was published before authoritative observation persisted', writes,
    )


def test_floor_refusal_survives_secondary_result_persistence_failure(tmp_path, monkeypatch):
    from core.audit.tests.test_dark_verify_parallel import _floor_error
    cfg = _config(tmp_path)
    result = _result([_outcome(0)])
    before = _snapshot(result)
    refusal = _floor_error()
    failure = OSError(errno.EIO, 'owned refusal-record persistence fault')
    executions, writes = [], []

    def nonexecuting_refusal(spec, target_root, **kwargs):
        executions.append(spec.finding_key)
        raise refusal

    real_save = orch.save_json

    def reject_refusal_write(path, data, *args, **kwargs):
        if path.name == 'dark-verify-results.json':
            writes.append(data)
            raise failure
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(dark_verify, 'execute_witness', nonexecuting_refusal)
    monkeypatch.setattr(orch, 'save_json', reject_refusal_write)
    with pytest.raises(BaseException) as caught:
        _run(result, cfg, workers=1)
    assert executions == ['m0.py:f0']
    assert len(writes) == 1
    assert not (cfg.out_dir / 'dark-verify-results.json').exists()
    assert _snapshot(result) == before
    assert caught.value is refusal, (
        'typed containment refusal was replaced by secondary persistence error',
        type(caught.value).__name__,
    )


def test_success_retains_projection_before_live_status_change(tmp_path, monkeypatch):
    cfg = harness._config(tmp_path)
    result = harness._result([harness._outcome(0)])
    harness._stub_execute(monkeypatch, {'f0'})
    writes = []
    real_save = orch.save_json

    def observe(path, data, *args, **kwargs):
        if path.name == 'dark-verify-results.json':
            writes.append((result.outcomes[0].status, result.findings, data[0]['status']))
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(orch, 'save_json', observe)
    harness._run(result, cfg, workers=1)
    assert writes == [('dark', 0, 'finding')]
    assert result.outcomes[0].status == 'finding' and result.findings == 1
    assert json.loads((cfg.out_dir / 'dark-verify-results.json').read_text())[0]['status'] == 'finding'


def test_duplicate_outcome_identity_does_not_double_charge_promotion(tmp_path, monkeypatch):
    cfg = harness._config(tmp_path)
    outcome = harness._outcome(0)
    result = harness._result([outcome, outcome])
    harness._stub_execute(monkeypatch, {'f0'})
    harness._run(result, cfg, workers=1)
    assert result.outcomes[0] is outcome and result.outcomes[1] is outcome
    assert outcome.status == 'finding'
    assert result.findings == 1 and result.dormant == 1
    records = json.loads((cfg.out_dir / 'dark-verify-results.json').read_text())
    assert len(records) == 2 and all(row['status'] == 'finding' for row in records)


def test_floor_flush_retains_and_applies_completed_prefix_before_raise(tmp_path, monkeypatch):
    cfg = harness._config(tmp_path)
    result = harness._result([harness._outcome(0), harness._outcome(1)])
    refusal = harness._floor_error()
    executions, writes = [], []

    def execute(spec, target_root, **kwargs):
        executions.append(spec.function)
        if spec.function == 'f1':
            raise refusal
        return dark_verify.DarkVerifyResult(finding_key=spec.finding_key, verdict='confirmed',
                                           violation_observed=True, match_detail='nonexecuting fixture')

    real_save = orch.save_json

    def observe(path, data, *args, **kwargs):
        if path.name == 'dark-verify-results.json':
            writes.append((result.findings, [o.status for o in result.outcomes]))
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(dark_verify, 'execute_witness', execute)
    monkeypatch.setattr(orch, 'save_json', observe)
    with pytest.raises(type(refusal)) as caught:
        harness._run(result, cfg, workers=1)
    assert caught.value is refusal and executions == ['f0', 'f1']
    assert writes == [(0, ['dark', 'dark'])]
    assert [o.status for o in result.outcomes] == ['finding', 'dark']
    assert result.findings == 1 and result.dormant == 1
    records = json.loads((cfg.out_dir / 'dark-verify-results.json').read_text())
    assert records[0]['status'] == 'finding' and records[1]['verdict'] == 'error'


def test_serial_parallel_preserves_order_records_and_counters(tmp_path, monkeypatch):
    harness._stub_execute(monkeypatch, {'f0', 'f2'})
    serial = harness._result([harness._outcome(i) for i in range(4)])
    parallel = harness._result([harness._outcome(i) for i in range(4)])
    cfg_s, cfg_p = harness._config(tmp_path / 's'), harness._config(tmp_path / 'p')
    harness._run(serial, cfg_s, workers=1)
    harness._run(parallel, cfg_p, workers=4)
    assert harness._snapshot(serial) == harness._snapshot(parallel)
    assert json.loads((cfg_s.out_dir / 'dark-verify-results.json').read_text()) == json.loads(
        (cfg_p.out_dir / 'dark-verify-results.json').read_text())


def test_write_cancellation_preserves_prior_assessment(tmp_path, monkeypatch):
    cfg = harness._config(tmp_path)
    result = harness._result([harness._outcome(0)])
    before = harness._snapshot(result)
    harness._stub_execute(monkeypatch, {'f0'})
    failure = KeyboardInterrupt('owned result write cancellation')

    def cancel_write(path, data, *args, **kwargs):
        assert path.name == 'dark-verify-results.json'
        raise failure

    monkeypatch.setattr(orch, 'save_json', cancel_write)
    with pytest.raises(KeyboardInterrupt) as caught:
        harness._run(result, cfg, workers=1)
    assert caught.value is failure
    assert harness._snapshot(result) == before
    assert not (cfg.out_dir / 'dark-verify-results.json').exists()


def test_floor_write_cancellation_keeps_existing_cancellation_policy(tmp_path, monkeypatch):
    cfg = harness._config(tmp_path)
    result = harness._result([harness._outcome(0)])
    before = harness._snapshot(result)
    refusal = harness._floor_error()
    cancellation = KeyboardInterrupt('owned refusal write cancellation')
    executions = []

    def refuse(spec, target_root, **kwargs):
        executions.append(spec.finding_key)
        raise refusal

    def cancel_write(path, data, *args, **kwargs):
        assert path.name == 'dark-verify-results.json'
        raise cancellation

    monkeypatch.setattr(dark_verify, 'execute_witness', refuse)
    monkeypatch.setattr(orch, 'save_json', cancel_write)
    with pytest.raises(KeyboardInterrupt) as caught:
        harness._run(result, cfg, workers=1)
    assert caught.value is cancellation and executions == ['m0.py:f0']
    assert harness._snapshot(result) == before
    assert not (cfg.out_dir / 'dark-verify-results.json').exists()
