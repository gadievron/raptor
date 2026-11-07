"""Summary error reporting preserves loss state, retained bytes and I/O identity."""
import errno
import json
import logging
import os

import pytest

from core.sandbox import summary, telemetry_mac
from core.testing.module_bindings import patch_module_attribute
from core.testing.sandbox_state_scope import isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


PAYLOAD = b'{"type":"write","path":"/owned/evidence"}\n'


@pytest.fixture
def owned(tmp_path, caplog):
    with isolated_sandbox_state(()), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / 'state')
        patch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        patch.setattr(summary, '_log_security_event', lambda *a, **kw: None)
        patch.setattr(telemetry_mac, 'mint', lambda fields: None)
        run = tmp_path / 'run'
        run.mkdir()
        caplog.set_level(logging.WARNING, logger=summary.logger.name)
        yield run


@pytest.fixture
def monkeypatch(owned):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


class _IO:
    def __init__(self):
        self.native_open, self.native_replace = os.open, os.replace
        self.native_read, self.native_close = os.read, os.close
        self.source = self.stage = self.problem = None
        self.active, self.claimed = set(), set()
        self.opened, self.closed = [], []

    def replace(self, src, dst):
        if self.stage == 'rename' and os.fspath(src) == str(self.source):
            raise self.problem
        return self.native_replace(src, dst)

    def open(self, path, *args, **kwargs):
        selected = os.fspath(path).startswith(str(self.source) + '.summarising.')
        if selected and self.stage == 'open':
            raise self.problem
        fd = self.native_open(path, *args, **kwargs)
        self.active.add(fd)
        if selected:
            self.claimed.add(fd)
            self.opened.append(fd)
        return fd

    def read(self, fd, count):
        if fd in self.claimed and self.stage == 'read':
            raise self.problem
        return self.native_read(fd, count)

    def close(self, fd):
        assert fd in self.active, 'unowned or duplicate summary close'
        self.active.remove(fd)
        self.native_close(fd)
        if fd in self.claimed:
            self.claimed.remove(fd)
            self.closed.append(fd)

    def finish(self):
        for fd in list(self.active):
            self.active.remove(fd)
            self.native_close(fd)


@pytest.fixture
def summary_io(monkeypatch, request):
    io = _IO()
    request.addfinalizer(io.finish)
    patch_module_attribute(monkeypatch, summary, 'os', 'replace', io.replace)
    patch_module_attribute(monkeypatch, summary, 'os', 'open', io.open)
    patch_module_attribute(monkeypatch, summary, 'os', 'read', io.read)
    patch_module_attribute(monkeypatch, summary, 'os', 'close', io.close)
    return io


_CASES = [
    pytest.param(route, False, id=route) for route in (
        'evidence-open', 'loss-state-resolve', 'denial-append', 'floor-append',
        'marker-resolve', 'marker-serialize', 'marker-write', 'marker-pending',
        'marker-restore', 'rename', 'open', 'read', 'summary-write',
    )
] + [pytest.param(route, True, id=route+'-strict')
     for route in ('rename', 'open', 'read', 'summary-write')]


@pytest.mark.parametrize('route,strict', _CASES)
@pytest.mark.parametrize('kind', ['runtime', 'type', 'nonstring'])
def test_summary_formatting_failure_keeps_failure_contracts(owned, monkeypatch, caplog, summary_io, route, strict, kind):
    run, io = owned, summary_io
    calls = []
    parent = TypeError if route == 'marker-serialize' else OSError

    class Broken(parent):
        def __str__(self):
            calls.append('str')
            if kind == 'nonstring':
                return None
            raise (RuntimeError if kind == 'runtime' else TypeError)('owned formatting failure')

        def __repr__(self):
            calls.append('repr')
            raise AssertionError('repr must not be attempted')

    problem = Broken(errno.EIO, 'owned failure')
    io.problem = problem
    writer = summary.write_text_atomically
    encoder = summary.dumps_artifact

    def fail(*args, **kwargs):
        raise problem

    if route == 'evidence-open':
        cls = summary._evidence.EvidenceFile
        with monkeypatch.context() as patch:
            patch.setattr(cls, 'open', classmethod(fail))
            with summary._lock:
                assert summary._get_evidence_handle_locked(run) is None
            assert summary._evidence_open_failed and summary._evidence_next_open_attempt > 0
        summary._evidence_next_open_attempt = 0.0
        with summary._lock:
            assert summary._get_evidence_handle_locked(run) is not None
        assert not summary._evidence_open_failed
    elif route in ('loss-state-resolve', 'marker-resolve'):
        class RefusingPath(type(run)):
            def resolve(self, *args, **kwargs):
                raise problem
        if route == 'marker-resolve':
            monkeypatch.setattr(summary, 'Path', RefusingPath)
            assert summary.record_audit_degraded(run, reason='owned') is None
            assert summary._degraded_markers == {}
        else:
            assert summary._record_evidence_write_failure(RefusingPath(run)) is None
            assert summary._evidence_write_failures == {}
    elif route in ('denial-append', 'floor-append'):
        monkeypatch.setattr(summary, 'dumps_artifact', fail)
        if route == 'denial-append':
            summary.set_active_run_dir(run)
            assert summary.record_denial('owned', 1, 'write', path='/owned/evidence') is None
            assert summary.get_evidence_write_failure(run)
        else:
            assert summary.record_floor_refusal(run, floor='mount-ns', achievable='landlock', reason='owned') is None
            records = summary._floor_refusals[str(run.resolve())]
            assert len(records) == 1 and records[0]['reason'] == 'owned'
    elif route.startswith('marker-'):
        marker = run / summary.AUDIT_DEGRADED_FILE
        if route == 'marker-serialize':
            monkeypatch.setattr(summary, 'dumps_artifact', fail)
            assert summary.record_audit_degraded(run, reason='owned') is None
            assert not marker.exists() and summary._degraded_markers == {}
        else:
            if route == 'marker-pending':
                def prime(*args, **kwargs):
                    raise OSError(errno.EIO, 'owned pending publication')
                with monkeypatch.context() as patch:
                    patch.setattr(summary, 'write_text_atomically', prime)
                    summary.record_audit_degraded(run, reason='owned')
            elif route == 'marker-restore':
                summary.record_audit_degraded(run, reason='owned')
                marker.unlink()
            monkeypatch.setattr(summary, 'write_text_atomically', fail)
            if route == 'marker-write':
                assert summary.record_audit_degraded(run, reason='owned') is None
            else:
                assert summary.reassert_audit_degraded(run) is (route == 'marker-restore')
            payload = summary.get_audit_degraded(run)
            entry = summary._degraded_markers[str(run.resolve())]
            assert entry['restored'] is (route == 'marker-restore')
            assert not marker.exists() and payload['reason'] == 'owned'
            monkeypatch.setattr(summary, 'write_text_atomically', writer)
            assert summary.reassert_audit_degraded(run) is (route == 'marker-restore')
            assert json.loads(marker.read_text()) == payload
            assert summary.reassert_audit_degraded(run) is (route == 'marker-restore')
    else:
        path = run / '.audit' / summary.DENIALS_FILE
        path.parent.mkdir()
        path.write_bytes(PAYLOAD)
        io.source, io.stage = path, route
        output = run / summary.SUMMARY_FILE
        previous = b'{"previous":true}\n'
        output.write_bytes(previous)
        if route == 'summary-write':
            monkeypatch.setattr(summary, 'write_text_atomically', fail)
        if strict:
            with pytest.raises(OSError) as caught:
                summary.summarize_and_write(run, raise_on_io_error=True)
            assert caught.value is problem
        else:
            assert summary.summarize_and_write(run) is None
        assert output.read_bytes() == previous
        snapshots = list(path.parent.glob(path.name + '.summarising.*'))
        if route == 'rename':
            assert path.read_bytes() == PAYLOAD and snapshots == []
        else:
            assert not path.exists() and len(snapshots) == 1
            assert snapshots[0].read_bytes() == PAYLOAD
            snapshots[0].rename(path)
        assert io.opened == io.closed and not io.active
        io.stage = None
        monkeypatch.setattr(summary, 'write_text_atomically', writer)
        result = summary.summarize_and_write(run)
        assert result['total_denials'] == 1
        assert json.loads(output.read_text()) == result
        assert not path.exists() and not list(path.parent.glob(path.name + '.summarising.*'))
    monkeypatch.setattr(summary, 'dumps_artifact', encoder)
    assert calls and all(call == 'str' for call in calls)
    records = [record for record in caplog.records if record.name == summary.logger.name]
    assert any('exception message unavailable' in record.getMessage() for record in records)
    assert all(record.exc_info is None for record in records)
    assert io.opened == io.closed and not io.active


@pytest.mark.parametrize('route', ['inspect-root', 'list-root', 'inspect-child', 'single-finalize', 'sweep-finalize'])
@pytest.mark.parametrize('kind', ['runtime', 'type', 'nonstring'])
def test_summary_cli_formatting_failure_keeps_status_and_sweep_progress(owned, monkeypatch, capsys, route, kind):
    run = owned
    calls = []

    class BrokenIO(OSError):
        def __str__(self):
            calls.append('str')
            if kind == 'nonstring':
                return None
            raise (RuntimeError if kind == 'runtime' else TypeError)('owned CLI formatting failure')

        def __repr__(self):
            calls.append('repr')
            raise AssertionError('repr must not be used')

    problem = BrokenIO(errno.EIO, 'owned CLI I/O failure')
    real_path = type(run)

    class FaultPath(real_path):
        def is_dir(self):
            if (route == 'inspect-root' and self == run
                    or route == 'inspect-child' and self.name == 'bad'):
                raise problem
            return super().is_dir()

        def iterdir(self):
            if route == 'list-root' and self == run:
                raise problem
            return (type(self)(child) for child in super().iterdir())

    monkeypatch.setattr(summary, 'Path', FaultPath)
    original = summary.summarize_and_write
    visited = []

    def finalize(path, **kwargs):
        visited.append(path.name)
        if route == 'single-finalize' or route == 'sweep-finalize' and path.name == 'bad':
            raise problem
        return original(path, **kwargs)

    monkeypatch.setattr(summary, 'summarize_and_write', finalize)
    sweep = route in ('list-root', 'inspect-child', 'sweep-finalize')
    if sweep:
        for name in ['bad', 'good']:
            child = run / name
            (child / '.audit').mkdir(parents=True)
            (child / '.audit' / summary.DENIALS_FILE).write_bytes(PAYLOAD)
    else:
        (run / '.audit').mkdir()
        (run / '.audit' / summary.DENIALS_FILE).write_bytes(PAYLOAD)
    args = ['--sweep', str(run)] if sweep else [str(run)]
    assert summary._cli_main(args) == 1
    captured = capsys.readouterr()
    assert 'exception message unavailable' in captured.err
    assert all(character.isprintable() for character in captured.err.rstrip('\n'))
    assert calls == ['str']
    if route in ('inspect-child', 'sweep-finalize'):
        good = run / 'good'
        assert json.loads((good / summary.SUMMARY_FILE).read_text())['total_denials'] == 1
        assert not (good / '.audit' / summary.DENIALS_FILE).exists()
        assert (run / 'bad' / '.audit' / summary.DENIALS_FILE).read_bytes() == PAYLOAD
        assert 'good' in visited
    elif route in ('inspect-root', 'single-finalize'):
        assert (run / '.audit' / summary.DENIALS_FILE).read_bytes() == PAYLOAD
    else:
        assert visited == []
