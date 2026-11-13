"""Pre-swap spend-file reads keep primary errors during consumed close."""
import errno
import fcntl
import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.coverage import journal_compact as compact
from core.coverage.journal import JOURNAL_FILENAME, _MAX_JOURNAL_LINE_BYTES


@pytest.fixture
def journal(tmp_path, monkeypatch):
    path = tmp_path / JOURNAL_FILENAME
    row = b'{"schema_version":-1,"cost_usd":0.5}\n'
    original = row + b'\n'
    path.write_bytes(original)
    info = path.stat()
    state = SimpleNamespace(root=tmp_path, path=path, row=row, original=original,
                            identity=(info.st_dev, info.st_ino), primary=None, cleanup=None,
                            reads=[], streams=[], closes=0, fd=None, temp=None, temp_identity=None)

    class Reader(io.BufferedReader):
        def readline(self, size=-1):
            data = super().readline(size)
            state.reads.append((size, data))
            assert len(state.reads) <= 2
            with path.open('rb') as probe:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            if state.primary is not None:
                raise state.primary
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    class OwnedPath(type(Path())):
        def open(self, mode='r', *args, **kwargs):
            if self.name.startswith(compact._COMPACT_TMP_PREFIX):
                assert self.parent == tmp_path and mode == 'rb' and not args and not kwargs
                native = Path(str(self)).open(mode)
                info = os.fstat(native.fileno())
                assert info.st_size == len(row)
                state.fd, state.temp = native.fileno(), Path(str(self))
                state.temp_identity = (info.st_dev, info.st_ino)
                reader = Reader(native)
                state.streams.extend([native, reader])
                return reader
            return Path(str(self)).open(mode, *args, **kwargs)

    monkeypatch.setattr(compact, 'Path', OwnedPath)
    state.run = lambda: compact.compact_journal(tmp_path)
    try:
        yield state
    finally:
        for stream in reversed(state.streams):
            if not stream.closed:
                io.BufferedReader.close(stream)


def retired(journal):
    assert b''.join(data for _, data in journal.reads) == journal.row
    assert all(size == _MAX_JOURNAL_LINE_BYTES + 1 for size, _ in journal.reads)
    assert journal.closes == 1 and all(stream.closed for stream in journal.streams)
    with pytest.raises(OSError) as caught:
        os.fstat(journal.fd)
    assert caught.value.errno == errno.EBADF
    assert not journal.temp.exists()
    assert not list(journal.root.glob(compact._COMPACT_TMP_PREFIX + '*'))


def untouched(journal):
    assert journal.path.read_bytes() == journal.original
    info = journal.path.stat()
    assert (info.st_dev, info.st_ino) == journal.identity
    assert not list(journal.root.glob(JOURNAL_FILENAME + '.pre-compact*'))


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, OSError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_public_compact_spend_read_error_survives_consumed_close(journal, primary, cleanup):
    journal.primary = primary('after actual compacted spend line read')
    journal.cleanup = cleanup('after consumed spend reader close')
    with pytest.raises(primary) as caught:
        journal.run()
    assert caught.value is journal.primary
    retired(journal)
    untouched(journal)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, MemoryError])
def test_public_compact_fresh_spend_close_failure_stays_visible(journal, cleanup):
    journal.cleanup = cleanup('fresh spend-file close failure')
    with pytest.raises(cleanup) as caught:
        journal.run()
    assert caught.value is journal.cleanup
    retired(journal)
    untouched(journal)


def test_public_compact_healthy_reparse_preserves_spend_and_raw_row(journal):
    stats = journal.run()
    retired(journal)
    assert stats.spend_usd_before == stats.spend_usd_after == 0.5
    assert stats.rows_before == stats.rows_after == 1
    assert journal.path.read_bytes() == journal.row
    assert Path(stats.backup_path).read_bytes() == journal.original
    info = journal.path.stat()
    assert (info.st_dev, info.st_ino) == journal.temp_identity
