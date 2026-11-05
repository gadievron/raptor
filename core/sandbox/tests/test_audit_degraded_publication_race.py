"""Marker absence must be classified against state from before its probe."""
from contextlib import ExitStack
import errno
import json
import threading
from unittest.mock import Mock

import pytest

from core.sandbox import summary
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(summary, '_degraded_markers', {
        key: dict(entry) for key, entry in summary._degraded_markers.items()})
    events = Mock()
    monkeypatch.setattr(summary, '_log_security_event', events)
    return events


@pytest.mark.parametrize('publisher_kind', ['initial', 'retry', 'failed-initial'])
def test_publication_during_probe_is_not_tampering(tmp_path, monkeypatch, owned_state, publisher_kind):
    run = tmp_path / 'run'
    run.mkdir()
    key = str(run.resolve())
    marker = run / summary.AUDIT_DEGRADED_FILE
    entered, release, done = threading.Event(), threading.Event(), threading.Event()
    errors, writes = [], []
    original_write = summary.write_text_atomically
    original_read = summary._read_marker_bytes

    def fail_write(*args, **kwargs):
        raise OSError(errno.ENOSPC, 'initial storage unavailable')

    if publisher_kind == 'retry':
        with monkeypatch.context() as scoped:
            scoped.setattr(summary, 'write_text_atomically', fail_write)
            summary.record_audit_degraded(run, reason='audit unavailable')
        assert summary._degraded_markers[key]['persisted'] is False

    def blocked_write(*args, **kwargs):
        writes.append(args)
        if len(writes) == 1:
            entered.set()
            assert release.wait(5), 'publisher was not released'
            if publisher_kind == 'failed-initial':
                return fail_write(*args, **kwargs)
        return original_write(*args, **kwargs)

    def publisher():
        try:
            if publisher_kind == 'retry':
                summary.reassert_audit_degraded(run)
            else:
                summary.record_audit_degraded(run, reason='audit unavailable')
        except BaseException as error:
            errors.append(error)
        finally:
            done.set()

    def probe_then_publish(path):
        value = original_read(path)
        assert value is None, 'probe must precede publication'
        release.set()
        assert done.wait(5), 'publisher did not finish before probe returned'
        assert not errors, errors
        return value

    worker = threading.Thread(target=publisher)

    def join_worker():
        if worker.ident is not None:
            worker.join(5)
            assert not worker.is_alive(), 'marker publisher survived cleanup'

    with ExitStack() as cleanup:
        scoped = cleanup.enter_context(monkeypatch.context())
        cleanup.callback(join_worker)
        cleanup.callback(release.set)
        scoped.setattr(summary, 'write_text_atomically', blocked_write)
        worker.start()
        assert entered.wait(5), 'publisher did not reach marker write'
        # The retry publisher has already performed its own read by now.
        scoped.setattr(summary, '_read_marker_bytes', probe_then_publish)
        assert summary.reassert_audit_degraded(run) is False
        join_worker()
        assert not errors, errors
        owned_state.assert_not_called()
        assert summary._degraded_markers[key]['persisted'] is True
        assert summary._degraded_markers[key]['restored'] is False
        assert json.loads(marker.read_text())['reason'] == 'audit unavailable'

    # Once published, real deletion still produces sticky tamper evidence.
    marker.unlink()
    assert summary.reassert_audit_degraded(run) is True
    assert summary.reassert_audit_degraded(run) is True
    owned_state.assert_called_once()
    assert marker.is_file()
