"""An exited reader is not proof that capture reached EOF successfully."""
import io
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox import seatbelt_audit as audit


@pytest.mark.parametrize('error', [OSError('read failed'), RuntimeError('parser failed')])
def test_reader_failure_is_persisted_as_incomplete(tmp_path, monkeypatch, error):
    owner = audit.LogStreamer(tmp_path)

    class FailedStream:
        closed = False

        def __iter__(self):
            raise error

        def close(self):
            self.closed = True

    stream = FailedStream()
    owner._proc = SimpleNamespace(stdout=stream, terminate=Mock(), wait=Mock(return_value=0))
    owner._reader = Mock()
    owner._reader.is_alive.return_value = False
    summaries = []
    monkeypatch.setattr(owner, '_append_record_locked', summaries.append)
    owner._read_loop()
    assert owner._reader_failed is True
    assert stream.closed
    owner.stop()
    assert summaries[0]['reader_failed'] is True
    assert summaries[0]['reader_drained'] is False
    assert owner._stop_complete


def test_failure_after_a_record_preserves_record_and_failure_state(tmp_path, monkeypatch):
    owner = audit.LogStreamer(tmp_path)
    captured = []

    class FailedStream(io.StringIO):
        def __iter__(self):
            yield '{"eventMessage":"first"}\n'
            raise OSError('late read failure')

    owner._proc = SimpleNamespace(stdout=FailedStream())
    monkeypatch.setattr(audit, 'parse_log_entry', lambda entry, **kwargs: {'path': 'first'})
    monkeypatch.setattr(owner, '_filter_and_append', captured.append)
    owner._read_loop()
    assert captured == [{'path': 'first'}]
    assert owner._reader_failed is True


def test_clean_eof_remains_drained_without_failure_flag(tmp_path, monkeypatch):
    owner = audit.LogStreamer(tmp_path)
    owner._proc = SimpleNamespace(stdout=io.StringIO(''), terminate=Mock(), wait=Mock(return_value=0))
    summaries = []
    monkeypatch.setattr(owner, '_append_record_locked', summaries.append)
    owner._read_loop()
    owner.stop()
    assert summaries[0]['reader_drained'] is True
    assert 'reader_failed' not in summaries[0]
