"""Producer wait failures cannot skip audit finalization."""
import errno
import io
import subprocess
from unittest.mock import Mock

import pytest

from core.sandbox import seatbelt_audit as audit


@pytest.mark.parametrize('wait_results', [
    [OSError(errno.EIO, 'wait failed'), 0],
    [ChildProcessError(), 0],
    [subprocess.TimeoutExpired('log', 1), OSError(errno.EIO, 'wait failed')],
    [OSError(errno.EIO, 'first wait'), OSError(errno.EIO, 'second wait')],
    [OSError(errno.EIO, 'wait failed'), subprocess.TimeoutExpired('log', 1)],
])
def test_stop_finalizes_despite_wait_errors(tmp_path, monkeypatch, caplog, wait_results):
    owner = audit.LogStreamer(tmp_path)
    proc = Mock()
    proc.stdout = io.StringIO('')
    proc.wait.side_effect = wait_results
    owner._proc = proc
    reader = Mock()
    reader.is_alive.side_effect = [True, False]
    owner._reader = reader
    evidence = Mock()
    owner._evidence = evidence
    summaries = []
    monkeypatch.setattr(owner, '_append_record_locked', summaries.append)

    owner.stop(drain_timeout=0.2)
    proc.terminate.assert_called_once_with()
    proc.kill.assert_called_once_with()
    assert proc.wait.call_count == 2
    reader.join.assert_called_once_with(timeout=3.0)
    assert proc.stdout.closed
    assert owner._stopped.is_set()
    assert owner._capture_closed and owner._stop_complete
    evidence.close.assert_called_once_with()
    assert owner._evidence is None
    assert len(summaries) == 1
    assert summaries[0]['type'] == 'audit_summary'
    assert summaries[0]['reader_drained'] is True
    assert 'producer' in caplog.text
    owner.stop()
    assert proc.wait.call_count == 2
    assert len(summaries) == 1


def test_healthy_wait_does_not_kill_producer(tmp_path, monkeypatch):
    owner = audit.LogStreamer(tmp_path)
    proc = Mock()
    proc.stdout = io.StringIO('')
    proc.wait.return_value = 0
    owner._proc = proc
    summaries = []
    monkeypatch.setattr(owner, '_append_record_locked', summaries.append)
    owner.stop()
    proc.kill.assert_not_called()
    assert len(summaries) == 1
    assert owner._stop_complete
