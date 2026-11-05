"""A final verification result must not depend on a released descriptor."""
from contextlib import ExitStack
import os
import threading
from types import ModuleType

import pytest

from core.sandbox import evidence


def forbid_inspection(monkeypatch):
    local_os = ModuleType('closed_evidence_os')
    vars(local_os).update(vars(os))

    def forbidden(*args, **kwargs):
        raise AssertionError('closed evidence was inspected again')

    for name in ('stat', 'fstat', 'lseek'):
        setattr(local_os, name, forbidden)
    monkeypatch.setattr(evidence, 'os', local_os)


@pytest.mark.parametrize('outcome', ['clean', 'truncated', 'skipped'])
def test_verify_after_close_returns_final_result(tmp_path, monkeypatch, outcome):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    try:
        assert handle.write_line('complete record\n')
        if outcome == 'truncated':
            handle.path.write_bytes(b'')
        expected = outcome != 'truncated'
        assert handle.close(verify=outcome != 'skipped') is expected
        forbid_inspection(monkeypatch)
        assert handle.verify() is expected
        assert handle.close() is expected
        assert handle.write_line('after close\n') is False
    finally:
        handle.close(verify=False)


@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt])
def test_verify_after_interrupted_close_keeps_failed_result(tmp_path, monkeypatch, failure):
    error = failure('verification interrupted')

    def fail():
        raise error

    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(handle, '_verify_locked', fail)
            with pytest.raises(failure) as raised:
                handle.close()
        assert raised.value is error
        with pytest.raises(OSError):
            os.fstat(handle.fd)
        forbid_inspection(monkeypatch)
        assert handle.verify() is False
        assert handle.close() is False
    finally:
        handle.close(verify=False)


@pytest.mark.parametrize('truncated', [False, True], ids=['clean', 'truncated'])
def test_verify_racing_close_uses_one_final_check(tmp_path, monkeypatch, truncated):
    entered, release, verifier_started = threading.Event(), threading.Event(), threading.Event()
    calls, results, errors = [], [], []

    def paused_check():
        calls.append(True)
        entered.set()
        assert release.wait(5), 'verification was not released'
        return original()

    def run(operation, started=None):
        if started is not None:
            started.set()
        try:
            results.append(operation())
        except BaseException as error:
            errors.append(error)

    def join(worker):
        if worker.ident is not None:
            worker.join(5)
            assert not worker.is_alive(), 'evidence test worker survived cleanup'

    with ExitStack() as cleanup:
        handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
        cleanup.callback(handle.close, verify=False)
        original = handle._verify_locked
        closer = threading.Thread(target=run, args=(handle.close,))
        cleanup.callback(join, closer)
        verifier = threading.Thread(target=run, args=(handle.verify, verifier_started))
        cleanup.callback(join, verifier)
        cleanup.callback(release.set)
        assert handle.write_line('complete record\n')
        if truncated:
            handle.path.write_bytes(b'')
        monkeypatch.setattr(handle, '_verify_locked', paused_check)
        closer.start()
        assert entered.wait(5), 'close did not enter verification'
        verifier.start()
        assert verifier_started.wait(5), 'verifier did not start'
        release.set()
        join(closer)
        join(verifier)
        assert not errors, errors
        assert results == [not truncated, not truncated]
        assert len(calls) == 1
