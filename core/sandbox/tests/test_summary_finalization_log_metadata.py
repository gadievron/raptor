"""Finalization diagnostics are inert while native evidence and flags stay intact."""

import errno
import json
import logging
import os
from pathlib import Path
from types import ModuleType

import pytest

from core.sandbox import evidence, summary
from core.testing.sandbox_state_scope import isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'
PAYLOAD = b'{"type":"write","path":"/owned/evidence"}\n'
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='owned POSIX control paths')


@pytest.fixture(params=['control', 'long'])
def owned(tmp_path, request, caplog):
    with isolated_sandbox_state(()), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / 'state')
        patch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        run = tmp_path / CONTROL
        if request.param == 'long':
            run = run / ('a' * 100) / ('b' * 100)
        run.mkdir(parents=True)
        caplog.set_level(logging.WARNING, logger=summary.__name__)
        yield run, request.param


@pytest.fixture
def monkeypatch(owned):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def warnings(caplog):
    return [r for r in caplog.records if r.name == summary.__name__ and r.levelno >= logging.WARNING]


def assert_safe(records, layout, label):
    assert records and any(label in r.getMessage() for r in records)
    for record in records:
        rendered = logging.Formatter('%(message)s').format(record)
        assert all(c.isprintable() for c in rendered)
        assert len(rendered) < 1400
        assert record.levelno == logging.WARNING
        assert record.exc_info is None
        if layout == 'long':
            assert '...[+' in rendered


def source(run, data=PAYLOAD):
    path = evidence.evidence_write_path(run, summary.DENIALS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def fault_io(monkeypatch, request, path, stage):
    private = ModuleType('summary_finalization_os')
    vars(private).update(vars(os))
    monkeypatch.setattr(summary, 'os', private)
    error = OSError(errno.EIO, CONTROL, str(path))
    active, claimed = set(), set()
    opened, closed = [], []

    def release_if_needed(fd):
        if fd in active:
            os.close(fd)
            active.remove(fd)

    def replace(src, dst):
        if Path(src) == path and stage == 'rename':
            raise error
        return os.replace(src, dst)

    def open_fd(name, *args, **kwargs):
        selected = str(name).startswith(str(path) + '.summarising.')
        if selected and stage == 'open':
            raise error
        fd = os.open(name, *args, **kwargs)
        request.addfinalizer(lambda: release_if_needed(fd))
        active.add(fd)
        if selected:
            claimed.add(fd)
            opened.append(fd)
        return fd

    def fstat(fd):
        if fd in claimed and stage == 'stat':
            raise error
        return os.fstat(fd)

    def read(fd, count):
        if fd in claimed and stage == 'read':
            raise error
        return os.read(fd, count)

    def close(fd):
        os.close(fd)
        active.remove(fd)
        if fd in claimed:
            claimed.remove(fd)
            closed.append(fd)

    private.replace, private.open = replace, open_fd
    private.fstat, private.read, private.close = fstat, read, close
    return opened, closed


@pytest.mark.parametrize('stage', ['rename', 'open', 'stat', 'read', 'write-default', 'write-strict'])
def test_finalization_io_warnings_keep_retained_evidence(owned, monkeypatch, request, caplog, stage):
    run, layout = owned
    path = source(run)
    opened, closed = fault_io(monkeypatch, request, path, stage)
    output = run / summary.SUMMARY_FILE
    if stage.startswith('write'):
        output.mkdir()
        (output / 'owned-sentinel').write_bytes(b'preserve')
    else:
        output.write_bytes(b'{"previous":"summary"}\n')
    if stage == 'write-strict':
        with pytest.raises(OSError):
            summary.summarize_and_write(run, raise_on_io_error=True)
    else:
        assert summary.summarize_and_write(run) is None
    assert opened == closed
    snapshots = list(path.parent.glob(path.name + '.summarising.*'))
    if stage == 'rename':
        assert path.read_bytes() == PAYLOAD and not snapshots
    else:
        assert not path.exists()
        assert len(snapshots) == 1 and snapshots[0].read_bytes() == PAYLOAD
    if stage.startswith('write'):
        assert (output / 'owned-sentinel').read_bytes() == b'preserve'
        label = 'failed to write/replace'
    else:
        assert output.read_bytes() == b'{"previous":"summary"}\n'
        label = 'failed to rename' if stage == 'rename' else 'failed to open' if stage == 'open' else 'failed to read'
    records = warnings(caplog)
    assert len(records) == (2 if stage.startswith('write') else 1)
    assert_safe(records, layout, label)


@pytest.mark.parametrize('kind', ['corrupt', 'unverified', 'mixed'])
def test_integrity_warning_keeps_summary_flags_and_native_paths(owned, caplog, kind):
    run, layout = owned
    if kind == 'corrupt':
        path = source(run, PAYLOAD + b'invalid json\n')
    else:
        forged = {'type': summary.FLOOR_REFUSAL_TYPE, 'floor': 'mount-ns',
                  'achievable': 'landlock', 'reason': 'other-process'}
        if kind == 'mixed':
            summary.record_floor_refusal(run, floor='mount-ns', achievable='landlock',
                                         reason='parent refusal', remedies='owned remedy')
            path = evidence.resolve_read_path(run, summary.DENIALS_FILE)
            with path.open('ab') as stream:
                stream.write((json.dumps(forged) + '\n').encode())
        else:
            path = source(run, (json.dumps(forged) + '\n').encode())
    result = summary.summarize_and_write(run)
    assert result['run_dir'] == str(run)
    assert result['mac']
    assert json.loads((run / summary.SUMMARY_FILE).read_text()) == result
    assert not path.exists() and not list(path.parent.glob(path.name + '.summarising.*'))
    if kind == 'corrupt':
        assert result['corrupt_lines'] == 1 and result['total_denials'] == 1
        assert result['denials'][0]['path'] == '/owned/evidence'
        label = 'SANDBOX EVIDENCE TAMPER SUSPECTED'
    else:
        assert result['total_denials'] == 0
        assert result['floor_refusal_records_unverified'] == 1
        assert len(result['unverified_floor_refusals']) == 1
        if kind == 'mixed':
            assert result['total_floor_refusals'] == 1
            assert result['floor_refusals'][0]['reason'] == 'parent refusal'
            label = 'absent from parent memory'
        else:
            assert 'total_floor_refusals' not in result
            label = 'recorded by another process'
    assert_safe(warnings(caplog), layout, label)


@pytest.mark.parametrize('kind', ['pending', 'missing', 'altered', 'restore-error'])
def test_marker_recovery_warnings_keep_parent_payload_and_sticky_state(owned, monkeypatch, caplog, kind):
    run, layout = owned
    writer = summary.write_text_atomically
    error = OSError(errno.EIO, CONTROL, str(run))

    def refuse(*args, **kwargs):
        raise error

    if kind == 'pending':
        monkeypatch.setattr(summary, 'write_text_atomically', refuse)
    summary.record_audit_degraded(run, reason=CONTROL, instructions='owned recovery')
    payload = summary.get_audit_degraded(run)
    marker = run / summary.AUDIT_DEGRADED_FILE
    assert payload['reason'] == CONTROL
    if kind == 'altered':
        marker.write_bytes(b'{"altered":true}\n')
    elif kind != 'pending':
        marker.unlink()
    if kind == 'restore-error':
        monkeypatch.setattr(summary, 'write_text_atomically', refuse)
    caplog.clear()
    assert summary.reassert_audit_degraded(run) is (kind != 'pending')
    assert summary.get_audit_degraded(run) == payload
    records = warnings(caplog)
    assert len(records) == (2 if kind == 'restore-error' else 1)
    monkeypatch.setattr(summary, 'write_text_atomically', writer)
    if kind in {'pending', 'restore-error'}:
        assert not marker.exists()
        assert summary.reassert_audit_degraded(run) is (kind == 'restore-error')
    assert json.loads(marker.read_text()) == payload
    assert summary.reassert_audit_degraded(run) is (kind != 'pending')
    label = 'pending marker retry failed' if kind == 'pending' else 'MARKER TAMPER SUSPECTED'
    assert_safe(records, layout, label)


@pytest.mark.parametrize('kind', ['summary', 'marker'])
def test_healthy_output_preserves_metadata_without_warning(owned, caplog, kind):
    run, _layout = owned
    if kind == 'summary':
        source(run)
        result = summary.summarize_and_write(run)
        assert result['run_dir'] == str(run)
        assert result['total_denials'] == 1 and 'corrupt_lines' not in result
        assert json.loads((run / summary.SUMMARY_FILE).read_text()) == result
    else:
        summary.record_audit_degraded(run, reason=CONTROL, instructions='owned recovery')
        payload = summary.get_audit_degraded(run)
        assert summary.reassert_audit_degraded(run) is False
        assert json.loads((run / summary.AUDIT_DEGRADED_FILE).read_text()) == payload
        assert payload['reason'] == CONTROL
    assert not warnings(caplog)
