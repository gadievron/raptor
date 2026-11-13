"""Strict saved-CSV reporting retains read and validation errors during close."""
import csv
import errno
import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow import run_corpus, trust_report


HEADER = b'finding_id,label_verdict,validator_verdict,validator_label,fp_category\r\n'
TP = b'tp,true_positive,uncertain,uncertain,\r\n'
FP = b'fp,false_positive,not_exploitable,false_positive,missing_sanitizer_model\r\n'


@pytest.fixture
def saved(tmp_path, monkeypatch):
    path = tmp_path / 'owned.csv'
    payload = HEADER + TP + FP
    path.write_bytes(payload)
    state = SimpleNamespace(path=path, payload=payload, primary=None, cleanup=None,
                            fail_after=1, lines=[], streams=[], closes=0, fd=None)

    class Reader(io.TextIOWrapper):
        def __next__(self):
            line = super().__next__()
            state.lines.append(line)
            if state.primary is not None and len(state.lines) == state.fail_after:
                raise state.primary
            return line

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    class OwnedPath(type(Path())):
        def open(self, mode='r', *, encoding, newline):
            assert self == path and mode == 'r' and encoding == 'utf-8' and newline == ''
            native = io.FileIO(path, 'r')
            state.fd = native.fileno()
            info, expected = os.fstat(state.fd), path.stat()
            assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
            reader = Reader(native, encoding=encoding, newline=newline)
            state.streams.extend([native, reader])
            return reader

    def forbidden(*args, **kwargs):
        pytest.fail('saved CSV reporting must not replay a corpus or run validators')

    monkeypatch.setattr(trust_report, 'Path', OwnedPath)
    monkeypatch.setattr(run_corpus, 'iter_corpus', forbidden)
    monkeypatch.setattr(run_corpus, 'main', forbidden)
    state.run = lambda: trust_report.report(path)
    try:
        yield state
    finally:
        for stream in reversed(state.streams):
            if not stream.closed:
                io.TextIOWrapper.close(stream)
        if path.exists():
            assert path.read_bytes() == state.payload


def retired(saved):
    seen = ''.join(saved.lines).encode()
    assert seen and saved.payload.startswith(seen)
    assert saved.closes == 1 and all(stream.closed for stream in saved.streams)
    with pytest.raises(OSError) as caught:
        os.fstat(saved.fd)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('phase', [1, 2], ids=['header', 'row'])
@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, OSError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_public_strict_csv_read_error_survives_consumed_close(saved, phase, primary, cleanup):
    saved.primary = primary('after actual native CSV line read')
    saved.cleanup = cleanup('after consumed CSV close')
    saved.fail_after = phase
    with pytest.raises(primary) as caught:
        saved.run()
    assert caught.value is saved.primary and len(saved.lines) == phase
    retired(saved)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, MemoryError])
def test_public_strict_csv_fresh_close_failure_remains_visible(saved, cleanup):
    saved.cleanup = cleanup('fresh CSV close failure')
    with pytest.raises(cleanup) as caught:
        saved.run()
    assert caught.value is saved.cleanup
    retired(saved)


def test_public_strict_csv_healthy_metrics_are_unchanged(saved):
    result = saved.run()
    assert (result.total, result.tp, result.trust_fp, result.coverage_n) == (2, 1, 1, 1)
    assert (result.false_suppression_n, result.defer_n, result.suppressed_total,
            result.suppressed_on_fp) == (0, 1, 1, 1)
    assert result.coverage == result.suppression_precision == 1.0
    assert result.false_suppression_rate == 0.0 and result.is_sound
    retired(saved)


@pytest.mark.parametrize('payload,pattern', [
    (HEADER + TP + TP, 'duplicate finding_id'),
    (HEADER + TP.replace(b'true_positive', b'invalid'), 'label_verdict'),
    (HEADER + FP.replace(b'missing_sanitizer_model', b'invalid'), 'fp_category'),
    (HEADER + TP.replace(b'uncertain,uncertain', b'uncertain,true_positive'), 'inconsistent'),
    (HEADER.replace(b'finding_id,', b'finding_id,finding_id,'), 'duplicate CSV column'),
])
def test_public_strict_csv_validation_error_survives_close_failure(saved, payload, pattern):
    saved.payload = payload
    saved.path.write_bytes(payload)
    saved.cleanup = MemoryError('after consumed close during strict refusal')
    with pytest.raises(ValueError, match=pattern):
        saved.run()
    retired(saved)


def test_public_strict_csv_zero_tp_is_not_sound(saved):
    saved.payload = HEADER + FP
    saved.path.write_bytes(saved.payload)
    result = saved.run()
    assert result.tp == 0 and not result.is_sound and result.false_suppression_rate is None
    retired(saved)


def test_public_strict_csv_bad_quotes_still_refuse(saved):
    saved.payload = HEADER + b'"unfinished,true_positive,uncertain,uncertain,\r\n'
    saved.path.write_bytes(saved.payload)
    saved.cleanup = OSError('after close during quote refusal')
    with pytest.raises(csv.Error):
        saved.run()
    retired(saved)


def test_public_strict_csv_missing_file_still_raises(saved):
    saved.path.unlink()
    with pytest.raises(FileNotFoundError):
        saved.run()
    assert not saved.lines and not saved.streams and saved.closes == 0
