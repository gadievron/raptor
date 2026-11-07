"""Persistence diagnostics escape metadata without changing failure accounting."""
import errno
import json
import logging
import os
import threading

import pytest

from core import atomic_fs
from core.sandbox import context, evidence, proxy, summary, telemetry_mac
from core.security.log_sanitisation import has_nonprintable, sanitise_for_terminal


_PAYLOADS = [
    pytest.param('\nforged line', id='newline'),
    pytest.param('\x1b[2J', id='escape'),
    pytest.param('\u202ealtered', id='bidi'),
    pytest.param('\udc80', id='surrogate'),
    pytest.param('x' * 5000, id='long'),
]


@pytest.fixture
def output(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})
    monkeypatch.setattr(context, '_PROXY_PERSIST_LOCK', threading.Lock())
    monkeypatch.setattr(summary, '_proxy_persist_state', {})
    monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: 'owned-token')
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'owned-token')
    caplog.set_level(logging.DEBUG, logger=context.logger.name)
    return tmp_path


def _safe(records):
    assert records
    for record in records:
        assert not has_nonprintable(record.getMessage())
        assert len(record.getMessage()) < 1300
        assert record.exc_info is None and record.stack_info is None


def _failure(payload, io=False):
    if io:
        return OSError(errno.EIO, 'owned failure ' + payload)
    name = 'Owned' + (payload if payload != '\udc80' else 'Failure')
    return type(name, (RuntimeError,), {})('owned failure ' + payload)


@pytest.mark.parametrize('payload', _PAYLOADS)
@pytest.mark.parametrize('route', ['accounting', 'sidecar', 'excluded', 'open', 'nonregular', 'append', 'secondary'])
def test_proxy_persistence_diagnostics_keep_accounting(output, monkeypatch, request, caplog, payload, route):
    # Surrogates exercise exception text without requiring non-UTF-8 filenames.
    name = 'owned-' + ('surrogate' if payload == '\udc80' else payload if len(payload) < 200 else payload[:120])
    directory = output / name
    directory.mkdir()
    log = directory / proxy.PROXY_EVENTS_FILENAME
    sidecar = directory / proxy.PROXY_EVENTS_COUNT_FILENAME
    target = None
    problem = _failure(payload, io=route in ('sidecar', 'append'))

    def fail(*args, **kwargs):
        raise problem

    if route == 'accounting':
        monkeypatch.setattr(summary, 'record_proxy_persist_state', fail)
        monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: None)
    elif route == 'sidecar':
        sidecar.write_bytes(b'previous sidecar')
        monkeypatch.setattr(atomic_fs, 'write_text_atomically', fail)
    elif route == 'excluded':
        target = directory
    elif route == 'open':
        destination = output / 'destination'
        destination.write_bytes(b'owned destination')
        log.symlink_to(destination)
    elif route == 'nonregular':
        if not hasattr(os, 'mkfifo'):
            pytest.skip('requires owned FIFO support')
        os.mkfifo(log, 0o600)
        reader = os.open(log, os.O_RDONLY | os.O_NONBLOCK)
        request.addfinalizer(lambda: os.close(reader))
    elif route == 'append':
        monkeypatch.setattr(telemetry_mac, 'mint', fail)
    elif route == 'secondary':
        monkeypatch.setattr(context, '_write_proxy_count_sidecar', fail)

    if route in ('accounting', 'sidecar'):
        context._write_proxy_count_sidecar(directory, 7, {'earlier_failure'}, 'owned-run')
    else:
        events = [{'host': 'example.test', 'port': 443, 'result': 'allowed'}]
        context._persist_proxy_events(events, output=directory, target=target)
        assert events == [{'host': 'example.test', 'port': 443, 'result': 'allowed'}]

    state = summary.get_proxy_persist_state(directory)
    if route == 'accounting':
        assert state is None and not sidecar.exists()
    elif route == 'sidecar':
        assert state == {'expected_count': 7, 'flags': ['earlier_failure']}
        assert sidecar.read_bytes() == b'previous sidecar'
    elif route == 'excluded':
        assert state is None and not log.exists() and not sidecar.exists()
        assert context._PROXY_STREAM_STATE == {}
    elif route in ('open', 'nonregular'):
        persisted = json.loads(sidecar.read_text())
        assert persisted['count'] == 0 and 'persist_open_failure' in persisted['flags']
        assert state['expected_count'] == 0 and 'persist_open_failure' in state['flags']
        if route == 'open':
            assert destination.read_bytes() == b'owned destination'
    elif route == 'append':
        assert state['expected_count'] == 0 and 'persist_write_failure' in state['flags']
        assert log.read_bytes() == b''
    elif route == 'secondary':
        assert state is None
        assert json.loads(log.read_text())['seq'] == 0
        writer = next(iter(context._PROXY_STREAM_STATE.values()))
        assert writer['next_seq'] == 1 and 'persist_write_failure' in writer['flags']
    assert context._PROXY_PERSIST_LOCK.acquire(blocking=False)
    context._PROXY_PERSIST_LOCK.release()
    records = [record for record in caplog.records if record.name == context.logger.name]
    _safe(records)
    if route != 'accounting':
        displayed = sidecar if route == 'sidecar' else directory if route == 'excluded' else log
        assert any(sanitise_for_terminal(str(displayed)) in record.getMessage() for record in records)
    if route in ('accounting', 'sidecar', 'append', 'secondary'):
        assert any(sanitise_for_terminal(str(problem)) in record.getMessage() for record in records)


@pytest.mark.parametrize('payload', [_PAYLOADS[i] for i in (0, 1, 2, 4)])
def test_evidence_serialization_warning_retains_records(tmp_path, request, caplog, payload):
    handle = evidence.EvidenceFile.open(tmp_path, 'records.jsonl')
    request.addfinalizer(handle.close)
    assert handle.write_record({'kept': 1})
    before = handle.path.read_bytes()
    invalid_key = type('Invalid' + payload, (), {})()
    assert handle.write_record({invalid_key: 'value'}) is False
    assert handle.path.read_bytes() == before
    assert handle.write_record({'kept': 2})
    assert [json.loads(line) for line in handle.path.read_text().splitlines()] == [{'kept': 1}, {'kept': 2}]
    assert handle.verify()
    records = [record for record in caplog.records if record.name == evidence.logger.name]
    _safe(records)
