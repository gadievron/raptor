"""Source rechecks retain full-file identity with bounded temporary buffers."""

import hashlib

import pytest

from core.audit import refutation_source as source


@pytest.fixture
def opened_reads(monkeypatch):
    """Observe the consumer's real confined stream and own its lifetime."""
    real_open = source.open_regular_beneath
    opened = []

    class ObservedStream:
        def __init__(self, stream):
            self.stream = stream
            self.requests = []
            self.total = 0
            self.after_read = None

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, size):
            self.requests.append(size)
            data = self.stream.read(size)
            self.total += len(data)
            if self.after_read is not None:
                self.after_read(self)
            return data

    def observe(*args, **kwargs):
        stream = real_open(*args, **kwargs)
        if stream is None:
            return None
        # Register ownership before any assertions or callbacks can fail.
        wrapped = ObservedStream(stream)
        opened.append(wrapped)
        return wrapped

    monkeypatch.setattr(source, 'open_regular_beneath', observe)
    yield opened
    for wrapped in opened:
        wrapped.stream.close()


@pytest.mark.parametrize('size', [0, 262144, 262145, 1048576, 10485760],
                         ids=['empty', 'one-chunk', 'chunk-plus-one', 'multi-chunk', 'cap'])
def test_recheck_hashes_every_raw_byte_with_bounded_reads(tmp_path, opened_reads, size):
    data = (bytes(range(256)) * ((size + 255) // 256))[:size]
    path = tmp_path / 'record.c'
    path.write_bytes(data)
    identity = source.capture_source_identity(tmp_path, path.name)
    assert identity.sha256 == hashlib.sha256(data).hexdigest()
    assert identity.version == source._version(path.stat())
    stream, = opened_reads
    assert stream.total == size
    assert max(stream.requests) <= size + 1
    if size > source._HASH_CHUNK_BYTES:
        assert max(stream.requests) <= source._HASH_CHUNK_BYTES
    assert stream.stream.closed


def test_excerpt_validation_keeps_its_existing_text_path(tmp_path, opened_reads):
    data = b'// padding\r\n' * 30000 + b'int Read(void) { return 0; }\r\n'
    path = tmp_path / 'record.c'
    path.write_bytes(data)
    identity = source.capture_source_identity(tmp_path, path.name,
        excerpt='int Read(void) { return 0; }\n', line_start=30001)
    assert identity.sha256 == hashlib.sha256(data).hexdigest()
    stream, = opened_reads
    assert stream.requests == [len(data) + 1]
    assert stream.stream.closed


@pytest.mark.parametrize('mutation', ['grow', 'truncate', 'rewrite', 'read-error'],
                         ids=['growth-beyond-cap', 'truncation', 'same-size-rewrite', 'read-error'])
def test_midstream_changes_and_failures_refuse_identity(tmp_path, monkeypatch, opened_reads, mutation):
    monkeypatch.setattr(source, 'MAX_SOURCE_BYTES', 3 * source._HASH_CHUNK_BYTES)
    path = tmp_path / 'record.c'
    path.write_bytes(b'a' * (2 * source._HASH_CHUNK_BYTES))
    observed_open = source.open_regular_beneath

    def alter_after_first_read(stream):
        stream.after_read = None
        if mutation == 'grow':
            with path.open('ab') as writer:
                writer.write(b'b' * source.MAX_SOURCE_BYTES)
        elif mutation == 'truncate':
            path.write_bytes(b'')
        elif mutation == 'rewrite':
            with path.open('r+b') as writer:
                writer.write(b'b' * source._HASH_CHUNK_BYTES)
        else:
            raise OSError('owned read failure')

    def open_changing(*args, **kwargs):
        stream = observed_open(*args, **kwargs)
        stream.after_read = alter_after_first_read
        return stream

    monkeypatch.setattr(source, 'open_regular_beneath', open_changing)
    assert source.capture_source_identity(tmp_path, path.name) is None
    stream, = opened_reads
    assert stream.total <= 2 * source._HASH_CHUNK_BYTES + 1
    assert max(stream.requests) <= source._HASH_CHUNK_BYTES
    assert stream.stream.closed


def test_initial_oversize_file_is_refused_without_reading(tmp_path, monkeypatch, opened_reads):
    monkeypatch.setattr(source, 'MAX_SOURCE_BYTES', source._HASH_CHUNK_BYTES)
    path = tmp_path / 'record.c'
    path.write_bytes(b'a' * (source.MAX_SOURCE_BYTES + 1))
    assert source.capture_source_identity(tmp_path, path.name) is None
    stream, = opened_reads
    assert stream.requests == []
    assert stream.stream.closed
