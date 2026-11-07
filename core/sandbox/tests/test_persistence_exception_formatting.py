"""Best-effort diagnostics survive exceptions with broken string conversion."""
import errno
import json
import logging
import os
import threading

import pytest

from core import atomic_fs
from core.sandbox import context, evidence, proxy, summary, telemetry_mac
from core.testing.module_bindings import patch_module_attribute


class _Faults:
    def __init__(self):
        self.native_open, self.native_write = os.open, os.write
        self.native_lseek, self.native_close = os.lseek, os.close
        self.route = self.path = self.fd = self.problem = None
        self.released = False

    def open(self, path, *args, **kwargs):
        if self.route == 'open' and os.fspath(path) == str(self.path):
            raise self.problem
        return self.native_open(path, *args, **kwargs)

    def write(self, fd, data):
        if self.route == 'evidence-write' and fd == self.fd:
            raise self.problem
        return self.native_write(fd, data)

    def lseek(self, fd, *args):
        if self.route == 'evidence-verify' and fd == self.fd:
            raise self.problem
        return self.native_lseek(fd, *args)

    def close(self, fd):
        if self.route == 'evidence-close' and fd == self.fd:
            assert not self.released, 'owned close must not be retried'
            self.native_close(fd)
            self.released = True
            raise self.problem
        return self.native_close(fd)


@pytest.fixture
def native_faults(monkeypatch):
    faults = _Faults()
    patch_module_attribute(monkeypatch, context, 'os', 'open', faults.open)
    patch_module_attribute(monkeypatch, evidence, 'os', 'write', faults.write)
    patch_module_attribute(monkeypatch, evidence, 'os', 'lseek', faults.lseek)
    patch_module_attribute(monkeypatch, evidence, 'os', 'close', faults.close)
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})
    monkeypatch.setattr(context, '_PROXY_PERSIST_LOCK', threading.Lock())
    monkeypatch.setattr(summary, '_proxy_persist_state', {})
    monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: 'owned-token')
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'owned-token')
    return faults


@pytest.mark.parametrize('format_error', [RuntimeError, ValueError, TypeError], ids=['runtime', 'value', 'type'])
@pytest.mark.parametrize('route', ['accounting', 'sidecar', 'open', 'append', 'secondary',
                                  'evidence-write', 'evidence-serialize', 'evidence-verify', 'evidence-close'])
def test_diagnostic_format_failure_keeps_original_outcome(tmp_path, monkeypatch, request, caplog, native_faults, format_error, route):
    calls = []

    class BrokenMessage(OSError):
        def __str__(self):
            calls.append('str')
            raise format_error('owned formatting failure')

        def __repr__(self):
            raise AssertionError('repr must not be used as a fallback')

    problem = BrokenMessage(errno.EIO, 'owned I/O failure')
    faults = native_faults
    faults.route, faults.problem = route, problem
    faults.path = tmp_path / proxy.PROXY_EVENTS_FILENAME
    caplog.set_level(logging.DEBUG)

    def fail(*args, **kwargs):
        raise problem

    if route.startswith('evidence-'):
        handle = evidence.EvidenceFile.open(tmp_path, 'records.jsonl')
        request.addfinalizer(lambda: handle.close(verify=False))
        faults.fd = handle.fd
        if route == 'evidence-write':
            assert handle.write_record({'event': 'failed'}) is False
            assert handle.path.read_bytes() == b''
        elif route == 'evidence-serialize':
            def broken_encoder(*args, **kwargs):
                class BrokenEncoding(TypeError):
                    def __str__(self):
                        return str(problem)
                raise BrokenEncoding('owned encode failure')
            monkeypatch.setattr(evidence, 'dumps_artifact', broken_encoder)
            assert handle.write_record({'event': 'failed'}) is False
            assert handle.path.read_bytes() == b''
        elif route == 'evidence-verify':
            assert handle.verify() is False
        else:
            assert handle.close() is False
            assert handle.close() is False
            assert faults.released
            with pytest.raises(OSError):
                os.fstat(handle.fd)
        if route != 'evidence-close':
            faults.route = None
            assert handle.write_line('{"event":"recovered"}\n')
            assert handle.verify()
    else:
        if route == 'accounting':
            monkeypatch.setattr(summary, 'record_proxy_persist_state', fail)
            monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: None)
        elif route == 'sidecar':
            monkeypatch.setattr(atomic_fs, 'write_text_atomically', fail)
        elif route == 'append':
            monkeypatch.setattr(telemetry_mac, 'mint', fail)
        elif route == 'secondary':
            attempts = []
            def fail_sidecar(*args):
                attempts.append(True)
                if len(attempts) == 1:
                    raise RuntimeError('first sidecar failure')
                raise problem
            monkeypatch.setattr(context, '_write_proxy_count_sidecar', fail_sidecar)
        if route in ('accounting', 'sidecar'):
            previous = tmp_path / proxy.PROXY_EVENTS_COUNT_FILENAME
            previous.write_bytes(b'previous sidecar')
            context._write_proxy_count_sidecar(tmp_path, 7, {'earlier_failure'}, 'run')
            assert previous.read_bytes() == b'previous sidecar'
            state = summary.get_proxy_persist_state(tmp_path)
            assert state is None if route == 'accounting' else state['expected_count'] == 7
        else:
            context._persist_proxy_events([{'host': 'example.test', 'port': 443, 'result': 'allowed'}], output=tmp_path)
            state = summary.get_proxy_persist_state(tmp_path)
            if route == 'secondary':
                assert len(attempts) == 2
                assert json.loads(faults.path.read_text())['seq'] == 0
                writer = next(iter(context._PROXY_STREAM_STATE.values()))
                assert writer['next_seq'] == 1 and 'persist_write_failure' in writer['flags']
            else:
                flag = 'persist_open_failure' if route == 'open' else 'persist_write_failure'
                assert state['expected_count'] == 0 and flag in state['flags']
        assert context._PROXY_PERSIST_LOCK.acquire(blocking=False)
        context._PROXY_PERSIST_LOCK.release()
    assert calls
    records = [r for r in caplog.records if r.name in (context.logger.name, evidence.logger.name)]
    assert any('exception message unavailable' in r.getMessage() for r in records)
    assert all(r.exc_info is None for r in records)
