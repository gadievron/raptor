"""Differential observations are retained before stronger publication."""

import errno
import json
import time

import pytest

from core.audit import orchestrator as orch
from core.audit import dark_verify, collector
from core.audit.tests import test_differential_orchestration as harness
from core.audit.tests.test_dark_verify_parallel import _floor_error


def test_existing_assessment_requires_retained_differential_record(tmp_path, monkeypatch):
    calls = harness._install_fake(monkeypatch, harness._divergent)
    outcome = harness._outcome(status='dark')
    result = harness._result([outcome])
    client, model_calls = harness._seq_client(harness._VECTOR_JSON)
    failure = OSError(errno.EIO, 'owned differential result persistence fault')
    writes = []
    real_save = orch.save_json

    def reject(path, data, *args, **kwargs):
        if path.name == 'differential-results.json':
            writes.append((outcome.status, result.findings, result.dormant))
            raise failure
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(orch, 'save_json', reject)
    with pytest.raises(OSError) as caught:
        orch._run_differential_verification(result, harness._config(tmp_path),
            {'leads': [harness._lead()]}, llm_client=client)
    assert caught.value is failure
    assert len(calls) == 4 and len(model_calls) == 1
    assert len(writes) == 1
    assert not (tmp_path / 'differential-results.json').exists()
    assert (outcome.status, outcome.evidence_tool, result.findings, result.dormant) == ('dark', '', 0, 1), writes


def test_floor_refusal_survives_differential_record_write_failure(tmp_path, monkeypatch):
    config = harness._config(tmp_path)
    config.run_deadline_monotonic = time.monotonic() + 60.0
    outcome = harness._outcome(status='dark')
    result = harness._result([outcome])
    client, model_calls = harness._seq_client(harness._VECTOR_JSON)
    refusal = _floor_error()
    failure = OSError(errno.EIO, 'owned differential refusal persistence fault')
    executions, writes = [], []

    def refuse(spec, target_path, audit_run_dir=None, *, deadline_monotonic=None):
        assert deadline_monotonic is config.run_deadline_monotonic
        executions.append(spec.finding_key)
        raise refusal

    real_save = orch.save_json

    def reject(path, data, *args, **kwargs):
        if path.name == 'differential-results.json':
            writes.append(data)
            raise failure
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(dark_verify, 'execute_witness', refuse)
    monkeypatch.setattr(orch, 'save_json', reject)
    with pytest.raises(BaseException) as caught:
        orch._run_differential_verification(result, config,
            {'leads': [harness._lead()]}, llm_client=client)
    assert len(executions) == 1 and len(model_calls) == 1 and len(writes) == 1
    assert outcome.status == 'dark' and result.findings == 0
    assert not (tmp_path / 'differential-results.json').exists()
    assert caught.value is refusal, type(caught.value).__name__


def test_synthesized_assessment_waits_for_retained_differential_record(tmp_path, monkeypatch):
    calls = harness._install_fake(monkeypatch, harness._divergent)
    result = harness._result([])
    client, model_calls = harness._seq_client(harness._VECTOR_JSON)
    failure = OSError(errno.EIO, 'owned synthesized-result persistence fault')
    published, writes = [], []
    real_append = collector.append_journal_for_outcome
    real_save = orch.save_json

    def observe_publication(**kwargs):
        answer = real_append(**kwargs)
        published.append(kwargs['outcome'])
        return answer

    def reject(path, data, *args, **kwargs):
        if path.name == 'differential-results.json':
            writes.append((len(published), result.post_loop_mechanical))
            raise failure
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(collector, 'append_journal_for_outcome', observe_publication)
    monkeypatch.setattr(orch, 'save_json', reject)
    with pytest.raises(OSError) as caught:
        orch._run_differential_verification(result, harness._config(tmp_path),
            {'leads': [harness._lead()]}, llm_client=client)
    assert caught.value is failure
    assert len(calls) == 4 and len(model_calls) == 1 and len(writes) == 1
    assert not (tmp_path / 'differential-results.json').exists()
    assert published == [] and result.post_loop_mechanical == 0, writes


def test_missing_output_directory_withholds_stronger_assessment(tmp_path, monkeypatch):
    calls = harness._install_fake(monkeypatch, harness._divergent)
    outcome = harness._outcome(status='dark')
    result = harness._result([outcome])
    config = harness._config(tmp_path)
    config.out_dir = None
    client, model_calls = harness._seq_client(harness._VECTOR_JSON)
    synthesized = orch._run_differential_verification(result, config,
        {'leads': [harness._lead()]}, llm_client=client)
    assert len(calls) == 4 and len(model_calls) == 1
    assert synthesized == []
    assert (outcome.status, outcome.evidence_tool, result.findings, result.dormant) == ('dark', '', 0, 1)


@pytest.mark.parametrize('existing', [False, True], ids=['synthesized', 'existing'])
def test_successful_retention_precedes_projection_publication(tmp_path, monkeypatch, existing):
    calls = harness._install_fake(monkeypatch, harness._divergent)
    outcome = harness._outcome(status='dark')
    result = harness._result([outcome] if existing else [])
    client, model_calls = harness._seq_client(harness._VECTOR_JSON)
    writes, published = [], []
    real_save, real_append = orch.save_json, collector.append_journal_for_outcome

    def observe_append(**kwargs):
        answer = real_append(**kwargs)
        published.append(kwargs['outcome'])
        return answer

    def observe_write(path, data, *args, **kwargs):
        if path.name == 'differential-results.json':
            writes.append((outcome.status, result.findings, result.post_loop_mechanical,
                           len(published), data[0]['promoted']))
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(collector, 'append_journal_for_outcome', observe_append)
    monkeypatch.setattr(orch, 'save_json', observe_write)
    synthesized = orch._run_differential_verification(result, harness._config(tmp_path),
        {'leads': [harness._lead()]}, llm_client=client)
    assert writes == [('dark', 0, 0, 0, True)]
    assert len(calls) == 4 and len(model_calls) == 1
    records = json.loads((tmp_path / 'differential-results.json').read_text())
    assert records[0]['promoted'] is True
    if existing:
        assert synthesized == [] and published == []
        assert result.outcomes[0] is outcome and outcome.status == 'finding'
        assert result.findings == 1 and result.dormant == 0
    else:
        assert len(synthesized) == len(published) == 1
        assert synthesized[0].status == 'finding'
        assert synthesized[0].evidence_tool == 'differential:confirmed'
        assert result.findings == 0 and result.post_loop_mechanical == 1


def test_repeated_key_reuses_synthesized_identity_and_journal_charge(tmp_path, monkeypatch):
    calls = harness._install_fake(monkeypatch, harness._divergent)
    result = harness._result([])
    client, model_calls = harness._seq_client(harness._VECTOR_JSON, harness._VECTOR_JSON)
    published = []
    real_append = collector.append_journal_for_outcome

    def observe(**kwargs):
        answer = real_append(**kwargs)
        published.append(kwargs['outcome'])
        return answer

    monkeypatch.setattr(collector, 'append_journal_for_outcome', observe)
    leads = [harness._lead(), harness._lead(description='second scoped concern for the same unit')]
    synthesized = orch._run_differential_verification(result, harness._config(tmp_path),
        {'leads': leads}, llm_client=client)
    assert len(synthesized) == len(published) == 1
    assert len(calls) == 8 and len(model_calls) == 2
    assert result.post_loop_mechanical == 1 and result.findings == 0
    records = json.loads((tmp_path / 'differential-results.json').read_text())
    assert records[0]['fold']['applied'] == 'synthesized'
    assert records[1]['fold'] == {'applied': 'chain-extend', 'prior_status': 'finding'}
    assert published[0].body == synthesized[0].body


def test_optional_journal_failure_keeps_retained_assessment(tmp_path, monkeypatch):
    harness._install_fake(monkeypatch, harness._divergent)
    result = harness._result([])
    client, _ = harness._seq_client(harness._VECTOR_JSON)
    journal_calls = []

    def fail_append(**kwargs):
        assert (tmp_path / 'differential-results.json').exists()
        journal_calls.append(kwargs['outcome'])
        raise OSError(errno.EIO, 'owned optional journal fault')

    monkeypatch.setattr(collector, 'append_journal_for_outcome', fail_append)
    synthesized = orch._run_differential_verification(result, harness._config(tmp_path),
        {'leads': [harness._lead()]}, llm_client=client)
    assert len(synthesized) == len(journal_calls) == 1
    assert synthesized[0].status == 'finding'
    assert result.post_loop_mechanical == 0
    assert json.loads((tmp_path / 'differential-results.json').read_text())[0]['promoted'] is True


@pytest.mark.parametrize('floor', [False, True], ids=['promotion', 'refusal'])
def test_record_write_cancellation_keeps_prior_assessment(tmp_path, monkeypatch, floor):
    config = harness._config(tmp_path)
    config.run_deadline_monotonic = time.monotonic() + 60.0
    outcome = harness._outcome(status='dark')
    result = harness._result([outcome])
    client, _ = harness._seq_client(harness._VECTOR_JSON)
    cancellation = KeyboardInterrupt('owned differential record cancellation')
    refusal = _floor_error()
    if floor:
        def refuse(spec, target_path, audit_run_dir=None, *, deadline_monotonic=None):
            assert deadline_monotonic is config.run_deadline_monotonic
            raise refusal
        monkeypatch.setattr(dark_verify, 'execute_witness', refuse)
    else:
        harness._install_fake(monkeypatch, harness._divergent)
    real_save = orch.save_json

    def cancel(path, data, *args, **kwargs):
        if path.name == 'differential-results.json':
            raise cancellation
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(orch, 'save_json', cancel)
    with pytest.raises(KeyboardInterrupt) as caught:
        orch._run_differential_verification(result, config,
            {'leads': [harness._lead()]}, llm_client=client)
    assert caught.value is cancellation
    assert (outcome.status, outcome.evidence_tool, result.findings, result.dormant) == ('dark', '', 0, 1)
    assert not (tmp_path / 'differential-results.json').exists()


@pytest.mark.parametrize('existing', [False, True], ids=['synthesized-prefix', 'existing-prefix'])
def test_completed_prefix_retained_before_floor_refusal(tmp_path, monkeypatch, existing):
    config = harness._config(tmp_path)
    config.run_deadline_monotonic = time.monotonic() + 60.0
    first = harness._outcome(status='dark')
    second = orch.ReviewOutcome(file='pkg/other.py', function='other', status='dark',
                               body='second scoped concern', hypothesis='separate boundary')
    result = harness._result([first, second] if existing else [second])
    client, model_calls = harness._seq_client(harness._VECTOR_JSON, harness._VECTOR_JSON)
    refusal = _floor_error()
    calls, writes, published = [], [], []
    real_save, real_append = orch.save_json, collector.append_journal_for_outcome

    def execute(spec, target_path, audit_run_dir=None, *, deadline_monotonic=None):
        assert deadline_monotonic is config.run_deadline_monotonic
        calls.append(spec.function)
        if spec.function == 'other':
            raise refusal
        status, value = harness._divergent(spec)
        return dark_verify.DarkVerifyResult(finding_key=spec.finding_key, verdict='inconclusive',
            observed_status=status, actual_return=value if status == 'returned' else '',
            actual_exception=value if status == 'exception' else '')

    def observe_append(**kwargs):
        answer = real_append(**kwargs)
        published.append(kwargs['outcome'])
        return answer

    def observe_write(path, data, *args, **kwargs):
        if path.name == 'differential-results.json':
            writes.append((first.status, result.findings, result.post_loop_mechanical, len(published)))
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(dark_verify, 'execute_witness', execute)
    monkeypatch.setattr(collector, 'append_journal_for_outcome', observe_append)
    monkeypatch.setattr(orch, 'save_json', observe_write)
    leads = [harness._lead(), harness._lead(file='pkg/other.py', function='other')]
    with pytest.raises(type(refusal)) as caught:
        orch._run_differential_verification(result, config,
            {'leads': leads}, llm_client=client)
    assert caught.value is refusal
    assert len(calls) == 5 and len(model_calls) == 2
    assert writes == [('dark', 0, 0, 0)]
    assert second.status == 'dark'
    assert first.status == ('finding' if existing else 'dark')
    assert result.findings == (1 if existing else 0)
    assert result.post_loop_mechanical == (0 if existing else 1)
    assert len(published) == (0 if existing else 1)
    records = json.loads((tmp_path / 'differential-results.json').read_text())
    assert records[0]['promoted'] is True and records[1]['kind'] == 'floor-refusal'


def test_deferred_journal_keeps_creation_time_source_roots(tmp_path, monkeypatch):
    harness._install_fake(monkeypatch, harness._divergent)
    result = harness._result([])
    config = harness._config(tmp_path)
    first_root, later_root = tmp_path / 'study-first', tmp_path / 'study-later'
    first_root.mkdir()
    later_root.mkdir()
    config.study_root = first_root
    model_calls, bindings = [], []
    real_append = collector.append_journal_for_outcome

    def client(prompt, system):
        model_calls.append(prompt)
        if len(model_calls) == 2:
            config.study_root = later_root
        return harness._VECTOR_JSON

    def observe_append(**kwargs):
        bindings.append(dict(kwargs['source_roots']))
        return real_append(**kwargs)

    monkeypatch.setattr(collector, 'append_journal_for_outcome', observe_append)
    leads = [harness._lead(), harness._lead(description='second scoped concern for the same unit')]
    synthesized = orch._run_differential_verification(result, config,
        {'leads': leads}, llm_client=client)
    assert len(model_calls) == 2 and config.study_root == later_root
    assert len(synthesized) == len(bindings) == 1
    assert bindings == [{'target': tmp_path.resolve(), 'study': first_root.resolve()}]
