"""Mixed chunks preserve zero edges without large padding writes."""
import errno
import io
import os

import pytest

from core.project import relocate


@pytest.mark.parametrize('chunk_bytes', [7, 4096, 65536, 1024 * 1024], ids=['tiny', 'page', 'small', 'default'])
@pytest.mark.parametrize('layout', ['leading', 'trailing', 'both', 'hole', 'dense', 'islands'])
def test_copy_writes_only_data_spans_with_bounded_reads(tmp_path, monkeypatch, chunk_bytes, layout):
    gap = b'\x00' * (3 * chunk_bytes + 17)
    if layout == 'leading':
        payload, expected_written = gap + b'end', 3
    elif layout == 'trailing':
        payload, expected_written = b'begin' + gap, 5
    elif layout == 'both':
        payload, expected_written = gap + b'payload' + gap, 7
    elif layout == 'hole':
        payload, expected_written = gap, 0
    elif layout == 'dense':
        payload, expected_written = b'P' * len(gap), len(gap)
    else:
        payload, expected_written = b'begin' + gap + b'end', 8
    monkeypatch.setattr(relocate, '_COPY_CHUNK_BYTES', chunk_bytes)
    reads, writes = [], []
    class Reader(io.BytesIO):
        def seek(self, offset, whence=os.SEEK_SET):
            if whence not in (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END):
                raise OSError(errno.EINVAL, 'extent reporting unavailable')
            return super().seek(offset, whence)
        def read(self, size):
            assert 0 < size <= chunk_bytes
            result = super().read(size)
            reads.append(len(result))
            return result
    target = tmp_path / 'copy'
    with target.open('wb') as stream:
        class Writer:
            def write(self, data):
                assert data and data[0] and data[-1]
                writes.append(len(data))
                return stream.write(data)
            def seek(self, *args):
                return stream.seek(*args)
            def truncate(self, size):
                return stream.truncate(size)
        relocate._copy_sparse_contents(Reader(payload), Writer(), len(payload))
    assert sum(reads) == len(payload)
    assert sum(writes) == expected_written
    assert target.stat().st_size == len(payload)
    with target.open('rb') as output:
        for offset in range(0, len(payload), chunk_bytes):
            assert output.read(chunk_bytes) == payload[offset:offset + chunk_bytes]
        assert output.read(1) == b''


@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('phase', ['leading-seek', 'write', 'trailing-seek'])
def test_sparse_span_failures_keep_the_original_error(failure_type, phase):
    failure = failure_type('primary sparse span failure')
    reached = []
    output = io.BytesIO()
    class Writer:
        seeks = 0
        def seek(self, *args):
            self.seeks += 1
            if ((phase == 'leading-seek' and self.seeks == 1)
                    or (phase == 'trailing-seek' and self.seeks == 2)):
                reached.append(phase)
                raise failure
            return output.seek(*args)
        def write(self, data):
            assert data == b'payload'
            if phase == 'write':
                reached.append(phase)
                raise failure
            return output.write(data)
    payload = b'\x00' * 7 + b'payload' + b'\x00' * 7
    with pytest.raises(failure_type) as caught:
        relocate._copy_exact(io.BytesIO(payload), Writer(), len(payload))
    assert caught.value is failure
    assert reached == [phase]


@pytest.mark.parametrize('written', [0, 1, None])
def test_trimmed_span_short_writes_still_abort(written):
    calls = []
    class Writer:
        def seek(self, *args):
            pass
        def write(self, data):
            calls.append(data)
            return written
    payload = b'\x00' * 7 + b'payload' + b'\x00' * 7
    with pytest.raises(OSError, match='incomplete destination write'):
        relocate._copy_exact(io.BytesIO(payload), Writer(), len(payload))
    assert calls == [b'payload']
