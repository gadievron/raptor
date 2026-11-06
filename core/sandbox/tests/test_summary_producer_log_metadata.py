"""Expected producer failures log inert metadata without losing recovery state."""

import errno
import json
import logging
import os

import pytest

from core.sandbox import evidence, summary
from core.testing.sandbox_state_scope import isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'
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
    assert len(records) == 1
    record = records[0]
    rendered = logging.Formatter('%(message)s').format(record)
    assert label in rendered
    assert record.levelno == logging.WARNING
    assert record.exc_info is None
    assert all(c.isprintable() for c in rendered)
    assert len(rendered) < 1100
    if layout == 'long':
        assert '...[+' in rendered


def get_handle(run):
    with summary._lock:
        return summary._get_evidence_handle_locked(run)


def test_native_open_failure_warns_once_and_retries(owned, monkeypatch, caplog):
    run, layout = owned
    blocked = evidence.audit_dir_path(run)
    blocked.write_bytes(b'preserve blocked entry')
    clock = [100.0]
    monkeypatch.setattr(summary, '_monotonic', lambda: clock[0])
    assert get_handle(run) is None
    assert summary._evidence_open_failed is True
    deadline = summary._evidence_next_open_attempt
    assert deadline > clock[0]
    assert get_handle(run) is None
    failed = warnings(caplog)
    assert len(failed) == 1
    assert blocked.read_bytes() == b'preserve blocked entry'
    blocked.unlink()
    clock[0] = deadline + 1
    handle = get_handle(run)
    assert handle is not None
    assert summary._evidence_open_failed is False
    assert summary._evidence_next_open_attempt == 0.0
    assert handle.write_line('{"owned":"healthy"}\n') is True
    assert handle.path.read_bytes() == b'{"owned":"healthy"}\n'
    assert_safe(failed, layout, 'cannot open evidence file')


@pytest.mark.parametrize('stage', ['loss-state', 'audit-marker'])
@pytest.mark.parametrize('error_type', [OSError, RuntimeError])
def test_resolution_failure_metadata_and_healthy_retry(owned, monkeypatch, caplog, stage, error_type):
    run, layout = owned
    error = error_type(CONTROL + 'x' * 1000)

    class Unresolvable(type(run)):
        def resolve(self, strict=False):
            raise error

    def record(path):
        if stage == 'loss-state':
            summary._record_evidence_write_failure(path)
        else:
            summary.record_audit_degraded(path, reason='owned marker reason')

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(summary, 'Path', Unresolvable)
        record(Unresolvable(run))
    assert summary._evidence_write_failures == {}
    assert summary._degraded_markers == {}
    assert list(run.iterdir()) == []
    failed = warnings(caplog)
    record(run)
    if stage == 'loss-state':
        assert summary.get_evidence_write_failure(run) is True
        label = 'could not retain evidence failure state'
    else:
        assert json.loads((run / summary.AUDIT_DEGRADED_FILE).read_text())['reason'] == 'owned marker reason'
        label = 'cannot resolve run directory'
    assert_safe(failed, layout, label)


def prepare_append(run, monkeypatch):
    events = []

    def capture(*args, **kwargs):
        events.append((args, kwargs))

    monkeypatch.setattr(summary, '_log_security_event', capture)
    summary.set_active_run_dir(run)
    handle = get_handle(run)
    assert handle is not None
    return handle, events


def append(kind, run, *, recovery=False):
    if kind == 'denial':
        summary.record_denial('owned command', 1, 'write', path=str(run))
    else:
        summary.record_floor_refusal(run, floor='full', achievable='none',
                                     reason='recovered refusal' if recovery else 'owned refusal')


@pytest.mark.parametrize('kind', ['denial', 'refusal'])
@pytest.mark.parametrize('failure', ['return-false', 'oserror'])
def test_append_io_warning_preserves_loss_refusals_and_events(owned, monkeypatch, caplog, kind, failure):
    run, layout = owned
    handle, events = prepare_append(run, monkeypatch)
    error = OSError(errno.EIO, CONTROL + 'x' * 1000, str(run))

    def fail(line):
        if failure == 'return-false':
            return False
        raise error

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(handle, 'write_line', fail)
        append(kind, run)
    assert handle.path.read_bytes() == b''
    if kind == 'denial':
        assert summary.get_evidence_write_failure(run) is True
        assert summary._denial_count == 1
        assert events == [(('sandbox_denial', 'sandbox denied write: owned command'),
                           {'denial_type': 'write', 'returncode': 1, 'path': str(run)})]
    else:
        assert summary._floor_refusals[str(run.resolve())][0]['reason'] == 'owned refusal'
        assert events == []
    failed = warnings(caplog)
    append(kind, run, recovery=True)
    persisted = json.loads(handle.path.read_text())
    result = summary.summarize_and_write(run)
    if kind == 'denial':
        assert persisted['path'] == str(run)
        assert result['total_denials'] == 1
        assert result['evidence_write_failure'] is True
        assert summary.get_evidence_write_failure(run) is True
        assert summary._evidence_write_failures[str(run.resolve())] is False
        assert len(events) == 3
        assert events[0] == events[1]
        assert events[2] == (('sandbox_evidence_corrupt', f'denials evidence corrupt under {run}'),
                             {'corrupt_lines': 0, 'inode_mismatch': False,
                              'evidence_write_failure': True, 'planted_object': '',
                              'surviving_records': 1})
        label = 'record_denial: failed to append JSONL'
    else:
        assert persisted['reason'] == 'recovered refusal'
        assert result['total_floor_refusals'] == 2
        assert {r['reason'] for r in result['floor_refusals']} == {'owned refusal', 'recovered refusal'}
        assert str(run.resolve()) not in summary._floor_refusals
        label = 'record_floor_refusal: failed to append JSONL'
    assert_safe(failed, layout, label)


@pytest.mark.parametrize('kind', ['denial', 'refusal'])
def test_unexpected_append_failure_keeps_debug_traceback(owned, monkeypatch, caplog, kind):
    run, _ = owned
    handle, events = prepare_append(run, monkeypatch)
    error = RuntimeError('owned unexpected failure')

    def fail(line):
        raise error

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(handle, 'write_line', fail)
        append(kind, run)
    records = warnings(caplog)
    assert len(records) == 1
    assert records[0].exc_info[1] is error
    assert 'failed to append JSONL' in records[0].getMessage()
    assert handle.path.read_bytes() == b''
    if kind == 'denial':
        assert summary.get_evidence_write_failure(run) is True
        assert len(events) == 1
    else:
        assert len(summary._floor_refusals[str(run.resolve())]) == 1


@pytest.mark.parametrize('kind', ['denial', 'refusal'])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_append_cancellation_propagates(owned, monkeypatch, caplog, kind, error_type):
    run, _ = owned
    handle, _events = prepare_append(run, monkeypatch)
    error = error_type('owned cancellation')

    def fail(line):
        raise error

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(handle, 'write_line', fail)
        with pytest.raises(error_type) as caught:
            append(kind, run)
    assert caught.value is error
    assert warnings(caplog) == []
    assert handle.path.read_bytes() == b''


@pytest.mark.parametrize('error_type', [ValueError, TypeError, RecursionError])
def test_marker_serialization_warning_preserves_retry(owned, caplog, error_type):
    run, layout = owned
    error = error_type(CONTROL + 'x' * 1000)

    def fail(*args, **kwargs):
        raise error

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(summary, 'dumps_artifact', fail)
        summary.record_audit_degraded(run, reason=CONTROL, instructions='owned instructions')
    assert summary.get_audit_degraded(run) is None
    assert not (run / summary.AUDIT_DEGRADED_FILE).exists()
    failed = warnings(caplog)
    summary.record_audit_degraded(run, reason=CONTROL, instructions='owned instructions')
    payload = json.loads((run / summary.AUDIT_DEGRADED_FILE).read_text())
    assert payload['reason'] == CONTROL
    assert payload['instructions'] == 'owned instructions'
    assert_safe(failed, layout, 'marker serialization failed')


@pytest.mark.parametrize('failure', ['native', 'oserror', 'valueerror', 'typeerror'])
def test_marker_write_warning_retains_exact_payload_for_retry(owned, caplog, failure):
    run, layout = owned
    target = run / summary.AUDIT_DEGRADED_FILE
    if failure == 'native':
        target.mkdir()
        sentinel = target / 'owned-sentinel'
        sentinel.write_bytes(b'preserve existing output')
        summary.record_audit_degraded(run, reason=CONTROL, instructions='owned instructions')
        assert sentinel.read_bytes() == b'preserve existing output'
        sentinel.unlink()
        target.rmdir()
    else:
        error_type = {'oserror': OSError, 'valueerror': ValueError, 'typeerror': TypeError}[failure]
        error = error_type(CONTROL + 'x' * 1000)

        def fail(*args, **kwargs):
            raise error

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(summary, 'write_text_atomically', fail)
            summary.record_audit_degraded(run, reason=CONTROL, instructions='owned instructions')
        assert not target.exists()
    entry = summary._degraded_markers[str(run.resolve())]
    assert entry['persisted'] is False
    assert entry['restored'] is False
    payload = summary.get_audit_degraded(run)
    assert payload['reason'] == CONTROL
    assert payload['instructions'] == 'owned instructions'
    expected = (summary.dumps_artifact(payload, ensure_ascii=True) + '\n').encode()
    failed = warnings(caplog)
    summary.record_audit_degraded(run, reason='replacement must not win')
    assert summary.get_audit_degraded(run) == payload
    assert summary.reassert_audit_degraded(run) is False
    assert target.read_bytes() == expected
    assert entry['persisted'] is True
    assert entry['restored'] is False
    assert_safe(failed, layout, 'marker write failed; retaining state')
