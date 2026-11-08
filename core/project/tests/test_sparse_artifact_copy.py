"""Artifact copies retain holes, bound work and preserve sources on failures."""
import errno
import io
import os

import pytest

from core.project import merge, relocate
from core.project.tests.test_directory_relocation import cross_device
from core.testing.module_bindings import patch_module_attribute


SIZE = 8 * 1024 * 1024 + 17
LAYOUTS = ['empty', 'hole', 'leading', 'trailing', 'islands']
MODES = ['native', 'portable', 'unsupported-data', 'unsupported-hole', 'conservative']


def make_sparse(path, layout):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('wb') as stream:
        if layout == 'empty':
            return
        if layout in {'trailing', 'islands'}:
            stream.write(b'begin')
        if layout == 'islands':
            stream.seek(SIZE // 2)
            stream.write(b'middle')
        if layout in {'leading', 'islands'}:
            stream.seek(SIZE - 3)
            stream.write(b'end')
        stream.truncate(SIZE)


class ExtentReader:
    """Keep real buffered IO; only the filesystem extent operation differs."""
    def __init__(self, reader, mode):
        self.reader = reader
        self.mode = mode
        self.bytes_read = 0

    def seek(self, offset, whence=os.SEEK_SET):
        if self.mode == 'conservative':
            if whence == getattr(os, 'SEEK_DATA', None):
                return self.reader.seek(offset)
            if whence == getattr(os, 'SEEK_HOLE', None):
                return self.reader.seek(0, os.SEEK_END)
        if ((self.mode == 'unsupported-data' and whence == getattr(os, 'SEEK_DATA', None))
                or (self.mode == 'unsupported-hole' and whence == getattr(os, 'SEEK_HOLE', None))):
            raise OSError(errno.EINVAL, 'test filesystem has no extent support')
        return self.reader.seek(offset, whence)

    def read(self, size):
        assert 0 < size <= relocate._COPY_CHUNK_BYTES
        block = self.reader.read(size)
        self.bytes_read += len(block)
        return block


@pytest.fixture
def copy_mode(monkeypatch, request):
    mode = request.param
    if mode == 'portable':
        patch_module_attribute(monkeypatch, relocate, 'os', 'SEEK_DATA', None, raising=False)
        patch_module_attribute(monkeypatch, relocate, 'os', 'SEEK_HOLE', None, raising=False)
    original = relocate._copy_sparse_contents
    observations = []

    def copy(reader, writer, size):
        proxy = ExtentReader(reader, mode)
        original(proxy, writer, size)
        assert proxy.bytes_read <= size
        observations.append(proxy.bytes_read)

    monkeypatch.setattr(relocate, '_copy_sparse_contents', copy)
    return observations


def assert_copy(source, destination):
    before, after = source.stat(), destination.stat()
    assert before.st_size == after.st_size
    with source.open('rb') as left, destination.open('rb') as right:
        while block := left.read(1024 * 1024):
            assert right.read(len(block)) == block
        assert right.read(1) == b''
    if hasattr(before, 'st_blocks') and before.st_size > 4 * 1024 * 1024:
        if before.st_blocks * 512 < before.st_size // 2:
            # The portable fallback can materialize the chunks containing data,
            # but must preserve the large zero intervals between those chunks.
            assert after.st_blocks * 512 < before.st_size // 2


@pytest.mark.parametrize('copy_mode', MODES, indirect=True)
@pytest.mark.parametrize('layout', LAYOUTS)
def test_regular_copier_preserves_sparse_contents_and_allocation(tmp_path, copy_mode, layout):
    source, destination = tmp_path / 'source', tmp_path / 'copy'
    make_sparse(source, layout)
    source.chmod(0o640)
    os.utime(source, ns=(1_000_000_000, 2_000_000_000))
    relocate._regular_copier()(source, destination)
    assert_copy(source, destination)
    assert destination.stat().st_mode & 0o777 == 0o640
    assert destination.stat().st_mtime_ns == source.stat().st_mtime_ns
    assert len(copy_mode) == 1


@pytest.mark.parametrize('copy_mode', MODES, indirect=True)
@pytest.mark.parametrize('layout', LAYOUTS)
@pytest.mark.parametrize('location', ['root', 'nested', 'history'])
def test_merge_retains_sparse_artifacts(tmp_path, copy_mode, layout, location):
    source = tmp_path / 'run'
    parent = source / {'root': '', 'nested': 'artifacts', 'history': '.reporting'}[location]
    artifact = parent / 'data.bin'
    make_sparse(artifact, layout)
    output = tmp_path / 'merged'
    merge.merge_runs([source], output)
    copied, = output.rglob('data.bin')
    assert_copy(artifact, copied)
    assert source.is_dir()


@pytest.mark.parametrize('copy_mode', MODES, indirect=True)
@pytest.mark.parametrize('layout', LAYOUTS)
def test_cross_filesystem_move_retains_sparse_artifacts(tmp_path, monkeypatch, copy_mode, layout):
    source, destination = tmp_path / 'source', tmp_path / 'destination'
    artifact = source / 'data.bin'
    make_sparse(artifact, layout)
    # Save the original under the same owned fixture tree for byte comparison.
    reference = tmp_path / 'reference'
    make_sparse(reference, layout)
    cross_device(monkeypatch)
    assert relocate.move_directory(source, destination)
    assert not source.exists()
    assert_copy(reference, destination / 'data.bin')


@pytest.mark.parametrize('error', [errno.EPERM, errno.ENOSYS, errno.ENOTSUP, errno.EXDEV, errno.EMLINK])
def test_unsupported_destination_hardlinks_fall_back_to_sparse_copy(tmp_path, monkeypatch, error):
    first, alias = tmp_path / 'first', tmp_path / 'alias'
    make_sparse(first, 'islands')
    os.link(first, alias)
    copy = relocate._regular_copier()
    destination = tmp_path / 'copy'
    copy(first, destination)
    calls = []

    def unsupported(*args, **kwargs):
        calls.append(True)
        raise OSError(error, 'test-owned link refusal')

    patch_module_attribute(monkeypatch, relocate, 'os', 'link', unsupported)
    second = tmp_path / 'second-copy'
    copy(alias, second)
    assert calls == [True]
    assert_copy(first, second)
    assert destination.stat().st_ino != second.stat().st_ino


@pytest.mark.parametrize('error', [errno.EIO, errno.ENOSPC, errno.EACCES, errno.EEXIST])
def test_hardlink_io_failures_are_not_retried_as_copies(tmp_path, monkeypatch, error):
    first, alias = tmp_path / 'first', tmp_path / 'alias'
    first.write_bytes(b'keep')
    os.link(first, alias)
    copy = relocate._regular_copier()
    copy(first, tmp_path / 'copy')

    def failed(*args, **kwargs):
        raise OSError(error, 'test-owned IO failure')

    patch_module_attribute(monkeypatch, relocate, 'os', 'link', failed)
    with pytest.raises(OSError) as caught:
        copy(alias, tmp_path / 'second-copy')
    assert caught.value.errno == error
    assert not (tmp_path / 'second-copy').exists()
    assert first.read_bytes() == b'keep'


def test_mutated_hardlink_is_not_replaced_with_stale_cached_bytes(tmp_path):
    first, alias = tmp_path / 'first', tmp_path / 'alias'
    first.write_bytes(b'old')
    os.link(first, alias)
    copy = relocate._regular_copier()
    copy(first, tmp_path / 'copy')
    first.write_bytes(b'new and larger')
    with pytest.raises(OSError, match='changed between copies'):
        copy(alias, tmp_path / 'second-copy')
    assert not (tmp_path / 'second-copy').exists()
    assert first.read_bytes() == b'new and larger'


@pytest.mark.parametrize('operation', ['merge', 'move'])
@pytest.mark.parametrize('mutation', ['grow-before', 'shrink-before', 'rewrite-after', 'empty-grow'])
def test_changed_sources_abort_publication_and_reclaim_staging(tmp_path, monkeypatch, operation, mutation):
    source = tmp_path / 'source'
    source.mkdir()
    path = source / 'data.bin'
    path.write_bytes(b'' if mutation == 'empty-grow' else b'original')
    original = relocate._copy_sparse_contents
    reads = []

    def changed(reader, writer, size):
        if mutation == 'grow-before':
            path.write_bytes(b'original plus appended data')
        elif mutation == 'shrink-before':
            path.write_bytes(b'x')
        elif mutation == 'empty-grow':
            path.write_bytes(b'grew')
        proxy = ExtentReader(reader, 'native')
        try:
            original(proxy, writer, size)
        finally:
            assert proxy.bytes_read <= size
            reads.append(True)
        if mutation == 'rewrite-after':
            path.write_bytes(b'rewritten after copy')

    monkeypatch.setattr(relocate, '_copy_sparse_contents', changed)
    destination = tmp_path / 'destination'
    if operation == 'move':
        cross_device(monkeypatch)
    with pytest.raises(OSError):
        if operation == 'move':
            relocate.move_directory(source, destination)
        else:
            merge.merge_runs([source], destination)
    assert reads == [True]
    assert path.exists()
    assert not destination.exists()
    assert not list(tmp_path.glob('.move-*'))
    assert not list(tmp_path.glob('.merge-stage-*'))


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('phase', ['read', 'write', 'truncate'])
def test_copy_io_and_cancellation_remain_primary_failures(tmp_path, failure, phase):
    source = tmp_path / 'data'
    source.write_bytes(b'payload')
    destination = io.BytesIO()

    class Reader(ExtentReader):
        def seek(self, offset, whence=os.SEEK_SET):
            if whence not in (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END):
                raise OSError(errno.EINVAL, 'no extent support')
            return super().seek(offset, whence)

        def read(self, size):
            if phase == 'read':
                raise failure('primary failure')
            return super().read(size)

    class Writer:
        def seek(self, *args):
            return destination.seek(*args)

        def write(self, block):
            if phase == 'write':
                raise failure('primary failure')
            return destination.write(block)

        def truncate(self, size):
            if phase == 'truncate':
                raise failure('primary failure')
            return destination.truncate(size)

    with source.open('rb') as reader, pytest.raises(failure, match='primary failure'):
        relocate._copy_sparse_contents(Reader(reader, 'native'), Writer(), source.stat().st_size)
    assert source.read_bytes() == b'payload'


@pytest.mark.parametrize('result', ['backwards', 'past-end', 'no-progress', 'hole-enxio'])
def test_invalid_extent_responses_refuse_without_losing_data(result):
    class Reader:
        def seek(self, offset, whence):
            if whence == os.SEEK_DATA:
                return -1 if result == 'backwards' else 100 if result == 'past-end' else 0
            if result == 'hole-enxio':
                raise OSError(errno.ENXIO, 'data disappeared')
            return 0
    if not hasattr(os, 'SEEK_DATA') or not hasattr(os, 'SEEK_HOLE'):
        pytest.skip('filesystem extent API unavailable on this host')
    with pytest.raises(OSError):
        relocate._copy_sparse_contents(Reader(), io.BytesIO(), 7)


def test_unknown_inode_ids_do_not_alias_distinct_hardlinked_sources(tmp_path, monkeypatch):
    sources = [tmp_path / 'first', tmp_path / 'second']
    for index, source in enumerate(sources):
        source.write_bytes(f'payload-{index}'.encode())
        os.link(source, tmp_path / f'alias-{index}')
    original = os.fstat

    def unknown_identity(fd):
        info = original(fd)
        values = list(info)
        values[1] = 0  # ST_INO, keeping the real stat_result shape.
        return os.stat_result(values, {
            'st_atime_ns': info.st_atime_ns, 'st_mtime_ns': info.st_mtime_ns,
            'st_ctime_ns': info.st_ctime_ns,
        })

    patch_module_attribute(monkeypatch, relocate, 'os', 'fstat', unknown_identity)
    copy = relocate._regular_copier()
    for index, source in enumerate(sources):
        destination = tmp_path / f'copy-{index}'
        copy(source, destination)
        assert destination.read_bytes() == source.read_bytes()
    assert (tmp_path / 'copy-0').stat().st_ino != (tmp_path / 'copy-1').stat().st_ino


@pytest.mark.parametrize('phase', ['data', 'hole'])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_extent_io_failure_is_not_an_unsupported_filesystem(phase, failure):
    if not hasattr(os, 'SEEK_DATA') or not hasattr(os, 'SEEK_HOLE'):
        pytest.skip('filesystem extent API unavailable on this host')

    class Reader:
        def seek(self, offset, whence):
            if whence == os.SEEK_DATA and phase == 'hole':
                return 0
            raise failure(errno.EIO, 'primary extent failure')

    output = io.BytesIO()
    with pytest.raises(failure, match='primary extent failure'):
        relocate._copy_sparse_contents(Reader(), output, 7)
    assert output.getvalue() == b''


@pytest.mark.parametrize('phase', ['data', 'hole'])
def test_unsupported_extents_after_progress_keep_the_copied_prefix(tmp_path, phase):
    if not hasattr(os, 'SEEK_DATA') or not hasattr(os, 'SEEK_HOLE'):
        pytest.skip('filesystem extent API unavailable on this host')
    source = tmp_path / 'source'
    make_sparse(source, 'islands')
    destination = tmp_path / 'copy'

    class Reader(ExtentReader):
        def seek(self, offset, whence=os.SEEK_SET):
            if whence == os.SEEK_DATA:
                if offset == 0:
                    return 0
                if phase == 'data':
                    raise OSError(errno.ENOTSUP, 'late unsupported extent')
                return SIZE // 2
            if whence == os.SEEK_HOLE:
                if offset == 0:
                    return 5
                raise OSError(errno.ENOTSUP, 'late unsupported extent')
            return super().seek(offset, whence)

    with source.open('rb') as reader, destination.open('wb') as writer:
        proxy = Reader(reader, 'native')
        relocate._copy_sparse_contents(proxy, writer, SIZE)
        assert proxy.bytes_read <= SIZE
    assert_copy(source, destination)


@pytest.mark.parametrize('read_size', [1, 7, 1024])
def test_short_reads_preserve_every_byte_and_the_trailing_hole(tmp_path, read_size):
    payload = b'a\x00b' * 3000 + b'\x00' * 17

    class Reader:
        def __init__(self):
            self.stream = io.BytesIO(payload)

        def seek(self, offset, whence=os.SEEK_SET):
            if whence not in (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END):
                raise OSError(errno.EINVAL, 'no extent support')
            return self.stream.seek(offset, whence)

        def read(self, size):
            return self.stream.read(min(size, read_size))

    destination = tmp_path / 'copy'
    with destination.open('wb') as output:
        relocate._copy_sparse_contents(Reader(), output, len(payload))
    assert destination.read_bytes() == payload


@pytest.mark.parametrize('written', [0, 1, None])
def test_short_writes_cannot_be_accepted_as_complete(written):
    class Writer:
        def write(self, block):
            return written
    with pytest.raises(OSError, match='incomplete destination write'):
        relocate._copy_exact(io.BytesIO(b'payload'), Writer(), 7)


def test_large_sparse_copy_reads_extents_without_scanning_the_holes(tmp_path):
    if not hasattr(os, 'SEEK_DATA') or not hasattr(os, 'SEEK_HOLE'):
        pytest.skip('filesystem extent API unavailable on this host')
    source = tmp_path / 'source'
    size = 1024 * 1024 * 1024
    with source.open('wb') as writer:
        writer.write(b'begin')
        writer.seek(size - 3)
        writer.write(b'end')
    with source.open('rb') as reader:
        try:
            hole = reader.seek(0, os.SEEK_HOLE)
            data = reader.seek(hole, os.SEEK_DATA)
        except OSError:
            pytest.skip('test filesystem does not report sparse extents')
        if hole > 8192 or data < size - 8192:
            pytest.skip('test filesystem conservatively reports the whole file as data')
    destination = tmp_path / 'copy'
    with source.open('rb') as reader, destination.open('wb') as writer:
        proxy = ExtentReader(reader, 'native')
        relocate._copy_sparse_contents(proxy, writer, size)
        assert proxy.bytes_read <= 16384
    assert destination.stat().st_size == size
    assert destination.stat().st_blocks * 512 <= 16384
    with destination.open('rb') as reader:
        assert reader.read(5) == b'begin'
        reader.seek(size // 2)
        assert reader.read(17) == b'\x00' * 17
        reader.seek(size - 3)
        assert reader.read(3) == b'end'
