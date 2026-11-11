"""Known retention failures are explicit coverage limitations, not verdicts.

All verification and model adapters are inert. Only owned result-file writes
use the filesystem; no compiler, target, provider or child process is run.
"""
from __future__ import annotations

import errno
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.audit import dark_verify
from core.audit import orchestrator as orch
from core.audit.tests import test_dark_verify_parallel as dark
from core.audit.tests import test_differential_orchestration as differential

MESSAGES = {
    'dark': 'new dark verification pass results (persistence failed)',
    'differential': 'new differential verification pass results (persistence failed)',
}
FILES = {'dark': 'dark-verify-results.json', 'differential': 'differential-results.json'}


def _setup(kind, tmp_path, monkeypatch, *, result=None, confirms=True):
    harness = dark if kind == 'dark' else differential
    outcome = dark._outcome(0) if kind == 'dark' else differential._outcome()
    if result is None:
        result = harness._result([outcome])
    config = harness._config(tmp_path)
    calls = []

    def execute(spec, target_root, **kwargs):
        calls.append(spec.finding_key)
        if kind == 'dark':
            return dark_verify.DarkVerifyResult(
                spec.finding_key, 'confirmed' if confirms else 'refuted',
                violation_observed=confirms, match_detail='inert observation',
            )
        status, value = (differential._divergent(spec) if confirms
                         else differential._agreeing(spec))
        return dark_verify.DarkVerifyResult(
            spec.finding_key, 'inconclusive', observed_status=status,
            actual_return=value if status == 'returned' else '',
            actual_exception=value if status == 'exception' else '',
        )

    monkeypatch.setattr(dark_verify, 'execute_witness', execute)

    def run():
        if kind == 'dark':
            return dark._run(result, config, workers=1)
        client, _ = differential._seq_client(differential._VECTOR_JSON)
        return orch._run_differential_verification(
            result, config, {'leads': [differential._lead()]}, llm_client=client,
        )

    return SimpleNamespace(kind=kind, result=result, config=config, calls=calls, run=run)


@pytest.fixture(params=('dark', 'differential'))
def operation(request, tmp_path, monkeypatch):
    return _setup(request.param, tmp_path, monkeypatch)


def _snapshot(result):
    return ([ (id(o), o.status, o.evidence_tool) for o in result.outcomes ],
            tuple(getattr(result, key) for key in (
                'reviewed', 'findings', 'suspicious', 'clean', 'errors', 'dormant',
                'post_loop_mechanical', 'total_cost_usd',
                'failed_attempts_cost_usd', 'llm_spend_usd')))


def _reject_write(monkeypatch, failure):
    writes = []
    real_save = orch.save_json

    def save(path, data, *args, **kwargs):
        if Path(path).name in FILES.values():
            writes.append(Path(path).name)
            raise failure
        return real_save(path, data, *args, **kwargs)

    monkeypatch.setattr(orch, 'save_json', save)
    return writes


def test_known_write_failure_sets_explicit_signal(operation, monkeypatch):
    op = operation
    op.result.total_cost_usd = 7.25
    before = _snapshot(op.result)
    failure = OSError(errno.EIO, 'private detail must not become public content')
    writes = _reject_write(monkeypatch, failure)
    with pytest.raises(OSError) as caught:
        op.run()
    assert caught.value is failure
    assert op.calls and writes == [FILES[op.kind]]
    assert _snapshot(op.result) == before
    assert getattr(op.result, 'processing_limitations', []) == [MESSAGES[op.kind]]


def test_default_lists_are_independent():
    first, second = orch.OrchestratorResult(), orch.OrchestratorResult()
    assert first.processing_limitations == second.processing_limitations == []
    first.processing_limitations.append(MESSAGES['dark'])
    assert second.processing_limitations == []


def test_original_floor_survives_writer_failure_with_signal(operation, monkeypatch):
    op = operation
    before = _snapshot(op.result)
    refusal = dark._floor_error()
    failure = OSError(errno.EIO, 'owned write failure')
    writes = _reject_write(monkeypatch, failure)

    def refuse(*args, **kwargs):
        op.calls.append('refusal')
        raise refusal

    monkeypatch.setattr(dark_verify, 'execute_witness', refuse)
    with pytest.raises(type(refusal)) as caught:
        op.run()
    assert caught.value is refusal and caught.value.__cause__ is failure
    assert writes == [FILES[op.kind]]
    assert _snapshot(op.result) == before
    assert op.result.processing_limitations == [MESSAGES[op.kind]]


@pytest.mark.parametrize('refused', [False, True])
def test_writer_cancellation_is_not_relabelled(operation, monkeypatch, refused):
    op = operation
    before = _snapshot(op.result)
    cancellation = KeyboardInterrupt()
    writes = _reject_write(monkeypatch, cancellation)
    if refused:
        refusal = dark._floor_error()

        def refuse(*args, **kwargs):
            raise refusal
        monkeypatch.setattr(dark_verify, 'execute_witness', refuse)
    with pytest.raises(KeyboardInterrupt) as caught:
        op.run()
    assert caught.value is cancellation
    assert writes == [FILES[op.kind]]
    assert _snapshot(op.result) == before
    assert op.result.processing_limitations == []


def test_ordinary_adapter_error_is_not_persistence_failure(operation, monkeypatch):
    op = operation
    fault = OSError(errno.EIO, 'ordinary adapter failure, not a result write')

    def fail(*args, **kwargs):
        op.calls.append('ordinary failure')
        raise fault

    monkeypatch.setattr(dark_verify, 'execute_witness', fail)
    try:
        op.run()
    except OSError as caught:
        assert caught is fault
    assert op.calls
    assert op.result.processing_limitations == []


def test_missing_output_is_not_inferred_write_failure(operation, monkeypatch):
    op = operation
    op.config.out_dir = None
    before = _snapshot(op.result)
    writes = _reject_write(monkeypatch, AssertionError('no known write expected'))
    if op.kind == 'dark':
        with pytest.raises(TypeError):
            op.run()
    else:
        assert op.run() == []
    assert op.calls and writes == []
    assert _snapshot(op.result) == before
    assert op.result.processing_limitations == []


@pytest.mark.parametrize('confirms', [False, True])
@pytest.mark.parametrize('kind', ['dark', 'differential'])
def test_healthy_retention_has_no_failure_signal(tmp_path, monkeypatch, kind, confirms):
    op = _setup(kind, tmp_path, monkeypatch, confirms=confirms)
    op.run()
    assert op.calls
    assert (op.config.out_dir / FILES[kind]).is_file()
    assert op.result.processing_limitations == []
    assert (op.result.findings > 0) is confirms


def test_retries_deduplicate_both_fixed_messages(tmp_path, monkeypatch):
    first = _setup('dark', tmp_path, monkeypatch)
    fault = OSError(errno.EIO, 'owned write failure')
    writes = _reject_write(monkeypatch, fault)
    for _ in range(2):
        with pytest.raises(OSError):
            first.run()
    second = _setup('differential', tmp_path, monkeypatch, result=first.result)
    for _ in range(2):
        with pytest.raises(OSError):
            second.run()
    assert writes == [FILES['dark']] * 2 + [FILES['differential']] * 2
    assert first.result.processing_limitations == list(MESSAGES.values())
