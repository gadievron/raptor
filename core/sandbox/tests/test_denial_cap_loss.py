"""The denial budget bounds storage without hiding evidence loss."""
import json

import pytest

from core.sandbox import summary, telemetry_mac, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_run_state(tmp_path):
    from core.testing.sandbox_state_scope import isolated_sandbox_state
    with isolated_sandbox_state(()):
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
            pin_user_state_dirs(patch, tmp_path / 'state')
            yield


@pytest.fixture
def monkeypatch(owned_run_state):
    """Undo body patches before restoring fixture-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def deny(count):
    for index in range(count):
        summary.record_denial(f'owned fixture {index}', 1, 'network')


@pytest.mark.parametrize('limit', [0, 2], ids=['zero-budget', 'two-records'])
def test_cap_loss_is_persisted_and_mac_bound(tmp_path, monkeypatch, caplog, limit):
    run = tmp_path / 'run'
    run.mkdir()
    monkeypatch.setattr(summary, 'MAX_DENIALS_PER_RUN', limit)
    summary.set_active_run_dir(run)
    deny(limit + 3)
    assert summary.get_evidence_write_failure(run)
    result = summary.summarize_and_write(run)
    assert result is not None
    assert result['total_denials'] == limit
    assert result['evidence_write_failure'] is True
    assert len([r for r in caplog.records if 'cap reached' in r.getMessage()]) == 1
    fields = telemetry_mac.summary_fields(
        limit, triage._denials_sha256(result['denials']), telemetry_mac.run_binding(run),
        evidence_write_failure=True)
    assert telemetry_mac.verify(fields, result['mac'])
    fields.pop('evidence_write_failure')
    assert not telemetry_mac.verify(fields, result['mac'])
    with monkeypatch.context() as scoped:
        scoped.setattr(summary, '_evidence_write_failures', {})
        report = triage.triage_run(run, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('limit', [0, 2], ids=['no-attempts', 'exact-budget'])
def test_reaching_budget_without_dropping_is_not_loss(tmp_path, monkeypatch, limit):
    run = tmp_path / 'run'
    run.mkdir()
    monkeypatch.setattr(summary, 'MAX_DENIALS_PER_RUN', limit)
    summary.set_active_run_dir(run)
    deny(limit)
    assert not summary.get_evidence_write_failure(run)
    result = summary.summarize_and_write(run)
    if limit:
        assert result['total_denials'] == limit
        assert 'evidence_write_failure' not in result
    else:
        assert result is None


def test_published_loss_is_idempotent_and_run_scoped(tmp_path, monkeypatch):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(summary, 'MAX_DENIALS_PER_RUN', 1)
    summary.set_active_run_dir(first)
    deny(2)
    result = summary.summarize_and_write(first)
    assert result['evidence_write_failure'] is True
    output = first / summary.SUMMARY_FILE
    before = output.read_bytes()
    deny(2)
    assert summary.summarize_and_write(first) is None
    assert output.read_bytes() == before
    summary.set_active_run_dir(second)
    deny(1)
    result = summary.summarize_and_write(second)
    assert result['total_denials'] == 1
    assert 'evidence_write_failure' not in result
    assert not summary.get_evidence_write_failure(second)
    assert json.loads(output.read_text())['evidence_write_failure'] is True
