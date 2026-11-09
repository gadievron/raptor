"""Bounded offline copies and complete ownership of prepare/import scratch."""

import hashlib
import logging
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.atomic_fs import rmtree_hardened
from core.run import scratch
from core.testing.scratch_state import isolated_scratch_keepalive
from packages.codeql import offline
from packages.codeql.tests import test_offline as offline_cases

setup = offline_cases.setup


@pytest.fixture
def transfer(setup, tmp_path, monkeypatch):
    roots = []
    original = tempfile.mkdtemp

    def allocate(*args, **kwargs):
        root = Path(original(*args, **kwargs))
        roots.append(root)
        return str(root)

    monkeypatch.setattr(scratch, 'tempfile', SimpleNamespace(**{**vars(tempfile), 'mkdtemp': allocate}))
    monkeypatch.setattr(scratch, 'logger', logging.Logger('offline-scratch-test'))
    try:
        with isolated_scratch_keepalive() as pins:
            yield SimpleNamespace(roots=roots, pins=pins, base=tmp_path, setup=setup)
            assert roots and all(not root.exists() for root in roots), roots
            assert not pins
    finally:
        for root in roots:
            assert rmtree_hardened(root)


def dirty(case):
    root = case.roots[-1]
    assert str(root) in case.pins
    child = root / 'cache-debris/restricted'
    if child.exists():
        child.chmod(0o700)
    child.mkdir(parents=True, exist_ok=True)
    (child / 'payload').write_bytes(b'cache' * 1024)
    child.chmod(0)


def prepared(case):
    kit = case.base / 'kit'
    digest = offline.prepare(kit, ['python'], ['standard', 'iris'])
    return kit, digest


@pytest.mark.parametrize('stage', ['download', 'install', 'resolve', 'check'])
@pytest.mark.parametrize('error', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_prepare_failure_reclaims_entire_workspace(transfer, monkeypatch, stage, error):
    def fail(*args, **kwargs):
        dirty(transfer)
        raise error('primary prepare failure')

    boot = offline._bootstrap()
    if stage in ('download', 'install'):
        monkeypatch.setitem(boot, '_download' if stage == 'download' else 'ensure_installed', fail)
    else:
        monkeypatch.setattr(offline, '_run' if stage == 'resolve' else '_check', fail)
    with pytest.raises(error, match='primary prepare failure'):
        prepared(transfer)
    assert not (transfer.base / 'kit').exists()


@pytest.mark.parametrize('stage', ['copy', 'install', 'source-check'])
@pytest.mark.parametrize('error', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_import_failure_reclaims_entire_workspace(transfer, monkeypatch, stage, error):
    kit, digest = prepared(transfer)
    before = offline._tree(kit)
    original_record, original_tree = offline._record, offline._tree

    def fail(*args, **kwargs):
        dirty(transfer)
        raise error('primary import failure')

    if stage == 'install':
        monkeypatch.setitem(offline._bootstrap(), 'ensure_installed', fail)
    elif stage == 'copy':
        def record(source, destination=None, **kwargs):
            if destination is not None and source.is_relative_to(kit):
                fail()
            return original_record(source, destination, **kwargs)
        monkeypatch.setattr(offline, '_record', record)
    else:
        def tree(root, **kwargs):
            if kwargs.get('source') and transfer.pins:
                fail()
            return original_tree(root, **kwargs)
        monkeypatch.setattr(offline, '_tree', tree)
    with pytest.raises(error, match='primary import failure'):
        offline.import_kit(kit, digest)
    assert original_tree(kit) == before


def test_prepare_and_import_success_keep_deliverables(transfer):
    kit, digest = prepared(transfer)
    before = offline._tree(kit)
    offline.import_kit(kit, digest)
    assert offline._tree(kit) == before
    _, pack, home, _ = transfer.setup
    assert (pack / offline.LOCK).is_file()
    assert (home / '.codeql/packages/codeql/python-all/1.0.0/qlpack.yml').is_file()


@pytest.mark.parametrize('operation', ['prepare', 'import'])
@pytest.mark.parametrize('error', [OSError, KeyboardInterrupt, SystemExit])
def test_secondary_workspace_cleanup_preserves_primary(transfer, monkeypatch, operation, error):
    if operation == 'import':
        kit, digest = prepared(transfer)

    def fail(*args, **kwargs):
        dirty(transfer)
        raise RuntimeError('primary tool failure')

    def remove(*args, **kwargs):
        raise error('secondary removal failure')

    boot = offline._bootstrap()
    monkeypatch.setitem(boot, '_download' if operation == 'prepare' else 'ensure_installed', fail)
    with pytest.MonkeyPatch.context() as fault:
        fault.setattr(scratch, 'rmtree_hardened', remove)
        with pytest.raises(RuntimeError, match='primary tool failure'):
            if operation == 'prepare':
                prepared(transfer)
            else:
                offline.import_kit(kit, digest)
    assert not transfer.pins
    for root in transfer.roots:
        assert rmtree_hardened(root)


@pytest.mark.parametrize('operation', ['prepare', 'import'])
@pytest.mark.parametrize('error', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_workspace_registration_failure_cleans_reservation(transfer, monkeypatch, operation, error):
    if operation == 'import':
        kit, digest = prepared(transfer)
    register = scratch.keepalive_register

    def fail(path):
        register(path)
        raise error('registration failure')

    monkeypatch.setattr(scratch, 'keepalive_register', fail)
    with pytest.raises(error, match='registration failure'):
        if operation == 'prepare':
            prepared(transfer)
        else:
            offline.import_kit(kit, digest)


@pytest.mark.parametrize('copy', [False, True], ids=['inventory', 'copy'])
def test_tree_checks_remaining_byte_budget_before_copy(tmp_path, monkeypatch, copy):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'a').write_bytes(b'123')
    (source / 'b').write_bytes(b'456')
    output = tmp_path / 'output'
    monkeypatch.setattr(offline, 'MAX_BYTES', 5)
    with pytest.raises(ValueError, match='bounded regular file'):
        offline._tree(source, copy_to=output if copy else None)
    if copy:
        assert (output / 'a').read_bytes() == b'123'
        assert not (output / 'b').exists()
        assert sum(p.stat().st_size for p in output.iterdir()) <= 5


@pytest.mark.parametrize('copy', [False, True], ids=['inventory', 'copy'])
def test_file_count_refuses_before_extra_file_is_copied(tmp_path, monkeypatch, copy):
    source = tmp_path / 'source'
    source.mkdir()
    for name in ('a', 'b'):
        (source / name).write_text(name)
    output = tmp_path / 'output'
    monkeypatch.setattr(offline, 'MAX_FILES', 1)
    with pytest.raises(ValueError, match='file budget'):
        offline._tree(source, copy_to=output if copy else None)
    if copy:
        assert [p.name for p in output.iterdir()] == ['a']


@pytest.mark.parametrize('nested', [False, True])
def test_directory_traversal_has_its_own_budget(tmp_path, monkeypatch, nested):
    source = tmp_path / 'source'
    source.mkdir()
    if nested:
        (source / 'one/two/three').mkdir(parents=True)
    else:
        for name in ('one', 'two', 'three'):
            (source / name).mkdir()
    monkeypatch.setattr(offline, 'MAX_DIRECTORIES', 2)
    with pytest.raises(ValueError, match='directory budget'):
        offline._tree(source)


def test_source_exclusions_do_not_consume_transfer_budgets(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    (source / '.git/one/two').mkdir(parents=True)
    (source / '.codeql/one/two').mkdir(parents=True)
    for name in (offline.LOCK, 'query.qlx', 'query.bqrs'):
        (source / name).write_bytes(b'x' * 20)
    (source / 'query.ql').write_bytes(b'q')
    monkeypatch.setattr(offline, 'MAX_FILES', 1)
    monkeypatch.setattr(offline, 'MAX_BYTES', 1)
    monkeypatch.setattr(offline, 'MAX_DIRECTORIES', 0)
    assert offline._tree(source, source=True) == {'query.ql': {'size': 1, 'sha256': hashlib.sha256(b'q').hexdigest()}}


def test_per_file_limit_refuses_before_destination_creation(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.write_bytes(b'123')
    output = tmp_path / 'output/file'
    monkeypatch.setattr(offline, 'MAX_FILE_BYTES', 2)
    with pytest.raises(ValueError, match='bounded regular file'):
        offline._record(source, output, max_bytes=100)
    assert not output.parent.exists()


def test_zero_byte_budget_accepts_empty_files(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'empty').touch()
    monkeypatch.setattr(offline, 'MAX_BYTES', 0)
    assert offline._tree(source, copy_to=tmp_path / 'output')['empty']['size'] == 0
    assert (tmp_path / 'output/empty').read_bytes() == b''


def test_growing_source_never_writes_beyond_budget(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.write_bytes(b'1234')
    output = tmp_path / 'output'
    original = offline.open_regular_gated
    requests = []
    streams = []

    class GrowingReader:
        def __init__(self, stream):
            self.stream = stream
            streams.append(stream)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def fileno(self):
            return self.stream.fileno()
        def read(self, size):
            requests.append(size)
            data = self.stream.read(size)
            if len(requests) == 1:
                with source.open('ab') as writer:
                    writer.write(b'56')
            return data

    monkeypatch.setattr(offline, '_COPY_CHUNK_BYTES', 2)
    monkeypatch.setattr(offline, 'open_regular_gated', lambda *a, **kw: GrowingReader(original(*a, **kw)))
    with pytest.raises(ValueError, match='grew beyond limit'):
        offline._record(source, output, max_bytes=4)
    assert output.stat().st_size <= 4
    assert requests[-1] == 1 and max(requests) <= 2
    assert all(stream.closed for stream in streams)


@pytest.mark.parametrize('shape', ['file', 'symlink', 'dangling'])
def test_existing_destination_is_never_overwritten(tmp_path, shape):
    source = tmp_path / 'source'
    source.write_bytes(b'copy')
    outside = tmp_path / 'operator'
    outside.write_bytes(b'operator')
    output = tmp_path / 'output'
    if shape == 'file':
        output.write_bytes(b'operator')
    else:
        output.symlink_to(outside if shape == 'symlink' else tmp_path / 'absent')
    with pytest.raises(FileExistsError):
        offline._record(source, output)
    assert outside.read_bytes() == b'operator'
    if shape == 'file':
        assert output.read_bytes() == b'operator'
    else:
        assert output.is_symlink()


@pytest.mark.parametrize('error', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_source_wrapper_failure_closes_open_descriptor(tmp_path, monkeypatch, error):
    from core.source import gated
    source = tmp_path / 'source'
    source.write_bytes(b'copy')
    descriptors = []
    original = os.open

    def open_fd(*args, **kwargs):
        fd = original(*args, **kwargs)
        descriptors.append(fd)
        return fd

    def fail(fd, mode, close_fd):
        try:
            close_fd(fd)
        except BaseException:
            pass
        raise error('source wrapper failed')

    monkeypatch.setattr(gated, 'os', SimpleNamespace(**{**vars(os), 'open': open_fd}))
    monkeypatch.setattr(gated, 'adopt_fd', fail)
    with pytest.raises(error, match='source wrapper failed'):
        offline._record(source, tmp_path / 'output')
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert not (tmp_path / 'output').exists()


def test_directory_swap_cannot_redirect_tree_copy(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    (source / 'nested').mkdir(parents=True)
    (source / 'nested/file').write_text('source')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'file').write_text('operator')
    original = offline._record

    def swap(path, destination=None, **kwargs):
        (source / 'nested').rename(source / 'retired')
        (source / 'nested').symlink_to(outside, target_is_directory=True)
        return original(path, destination, **kwargs)

    monkeypatch.setattr(offline, '_record', swap)
    with pytest.raises(ValueError, match='confined regular file'):
        offline._tree(source, copy_to=tmp_path / 'output')
    assert not (tmp_path / 'output').exists()
    assert (outside / 'file').read_text() == 'operator'


def test_import_refuses_growth_before_copying_or_installing(transfer, monkeypatch):
    kit, digest = prepared(transfer)
    original = offline._load_kit
    _, _, _, calls = transfer.setup
    calls.clear()

    def grow(*args, **kwargs):
        boot, data = original(*args, **kwargs)
        (kit / 'bundle.tar.gz').write_bytes(b'bundle' + b'x' * 32)
        return boot, data

    monkeypatch.setattr(offline, '_load_kit', grow)
    with pytest.raises(ValueError, match='bounded regular file'):
        offline.import_kit(kit, digest)
    assert not calls, 'changed transfer reached the installer'
