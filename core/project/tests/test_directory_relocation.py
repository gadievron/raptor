"""Directory moves keep sources and unrelated destinations on failed publication."""
import errno
import os
from pathlib import Path
import shutil

import pytest

from core.project import relocate


@pytest.fixture
def tree(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'data').write_bytes(b'run data')
    return source, tmp_path / 'destination'


def cross_device(monkeypatch):
    original = relocate.publish_new_directory
    def publish(source, destination):
        if Path(source).name == 'source':
            raise OSError(errno.EXDEV, 'different filesystems')
        return original(source, destination)
    monkeypatch.setattr(relocate, 'publish_new_directory', publish)


def occupy(path, kind, tmp_path):
    if kind in ('empty', 'populated'):
        path.mkdir()
        if kind == 'populated':
            (path / 'keep').write_text('bystander')
    elif kind == 'file':
        path.write_text('bystander')
    elif kind == 'fifo':
        os.mkfifo(path)
    else:
        target = tmp_path / 'borrowed'
        if kind == 'symlink':
            target.mkdir(exist_ok=True)
            (target / 'keep').write_text('bystander')
        path.symlink_to(target)
    return path.lstat().st_ino


@pytest.mark.parametrize('cross', [False, True], ids=['rename', 'copy'])
@pytest.mark.parametrize('kind', ['empty', 'populated', 'file', 'fifo', 'symlink', 'dangling'])
def test_occupied_exact_destination_never_nests_or_overwrites(tree, tmp_path, monkeypatch, cross, kind):
    source, destination = tree
    if cross:
        cross_device(monkeypatch)
    identity = occupy(destination, kind, tmp_path)
    with pytest.raises(OSError):
        relocate.move_directory(source, destination)
    assert destination.lstat().st_ino == identity
    assert (source / 'data').read_bytes() == b'run data'
    assert not list(tmp_path.glob('.move-*'))


@pytest.mark.parametrize('cross', [False, True], ids=['rename', 'copy'])
def test_success_moves_exact_path_preserving_links_without_reading_targets(tree, tmp_path, monkeypatch, cross):
    source, destination = tree
    outside = tmp_path / 'outside'
    outside.write_text('borrowed')
    (source / 'link').symlink_to(outside)
    (source / 'dangling').symlink_to(tmp_path / 'absent')
    before = source.stat().st_ino
    if cross:
        cross_device(monkeypatch)
    assert relocate.move_directory(source, destination)
    assert not source.exists()
    assert (destination / 'data').read_bytes() == b'run data'
    assert (destination / 'link').is_symlink()
    assert (destination / 'dangling').is_symlink()
    assert outside.read_text() == 'borrowed'
    if not cross:
        assert destination.stat().st_ino == before
    assert not list(tmp_path.glob('.move-*'))


@pytest.mark.parametrize('code', [errno.EACCES, errno.ENOSPC, errno.EIO, errno.ENOTSUP, errno.EROFS])
def test_only_exdev_permits_copy_fallback(tree, monkeypatch, code):
    source, destination = tree
    def denied(*args):
        raise OSError(code, 'rename failed')
    def copied(*args, **kwargs):
        pytest.fail('non-EXDEV errors must not allocate a duplicate tree')
    monkeypatch.setattr(relocate, 'publish_new_directory', denied)
    from core.testing.module_bindings import patch_module_attribute
    patch_module_attribute(monkeypatch, relocate, 'shutil', 'copytree', copied)
    with pytest.raises(OSError) as error:
        relocate.move_directory(source, destination)
    assert error.value.errno == code
    assert source.is_dir() and not destination.exists()


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('after', [False, True], ids=['before-copy', 'after-copy'])
def test_copy_failure_reclaims_partial_tree_and_preserves_source(tree, tmp_path, monkeypatch, failure, after):
    source, destination = tree
    cross_device(monkeypatch)
    def copy(src, dst, **kwargs):
        if after:
            shutil.copytree(src, dst, **kwargs)
        else:
            dst.mkdir()
            (dst / 'partial').write_text('partial')
        raise failure('copy failed')
    from core.testing.module_bindings import patch_module_attribute
    patch_module_attribute(monkeypatch, relocate, 'shutil', 'copytree', copy)
    with pytest.raises(failure, match='copy failed'):
        relocate.move_directory(source, destination)
    assert (source / 'data').read_bytes() == b'run data'
    assert not destination.exists()
    assert not list(tmp_path.glob('.move-*'))


@pytest.mark.parametrize('cross', [False, True], ids=['rename', 'copy'])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('after', [False, True], ids=['before-effect', 'after-effect'])
def test_publication_failure_restores_owned_effects(tree, tmp_path, monkeypatch, cross, failure, after):
    source, destination = tree
    original = relocate.publish_new_directory
    def publish(src, dst):
        if cross and src == source:
            raise OSError(errno.EXDEV, 'different filesystems')
        if after:
            original(src, dst)
        raise failure('publication failed')
    monkeypatch.setattr(relocate, 'publish_new_directory', publish)
    with pytest.raises(failure, match='publication failed'):
        relocate.move_directory(source, destination)
    assert (source / 'data').read_bytes() == b'run data'
    assert not destination.exists()
    assert not list(tmp_path.glob('.move-*'))


@pytest.mark.parametrize('cross', [False, True], ids=['rename', 'copy'])
@pytest.mark.parametrize('kind', ['empty', 'populated', 'file', 'fifo', 'symlink', 'dangling'])
def test_late_destination_contender_is_preserved(tree, tmp_path, monkeypatch, cross, kind):
    source, destination = tree
    original = relocate.publish_new_directory
    identities = []
    def publish(src, dst):
        if cross and src == source:
            raise OSError(errno.EXDEV, 'different filesystems')
        identities.append(occupy(dst, kind, tmp_path))
        original(src, dst)
    monkeypatch.setattr(relocate, 'publish_new_directory', publish)
    with pytest.raises(OSError):
        relocate.move_directory(source, destination)
    assert destination.lstat().st_ino == identities[0]
    assert (source / 'data').read_bytes() == b'run data'
    assert not list(tmp_path.glob('.move-*'))


@pytest.mark.parametrize('kind', ['symlink', 'dangling', 'fifo', 'file'])
def test_non_directory_source_is_never_relocated(tmp_path, kind):
    source = tmp_path / 'source'
    identity = occupy(source, kind, tmp_path)
    with pytest.raises(OSError):
        relocate.move_directory(source, tmp_path / 'destination')
    assert source.lstat().st_ino == identity


@pytest.mark.parametrize('relation', ['same', 'parent', 'child'])
def test_overlapping_moves_are_refused_before_mutation(tree, relation):
    source, destination = tree
    destination = {'same': source, 'parent': source.parent, 'child': source / 'nested'}[relation]
    with pytest.raises(ValueError, match='overlap'):
        relocate.move_directory(source, destination)
    assert (source / 'data').read_bytes() == b'run data'


@pytest.mark.parametrize('raises', [False, True], ids=['refused', 'io-error'])
def test_source_cleanup_failure_reports_both_complete_copies(tree, monkeypatch, caplog, raises):
    source, destination = tree
    cross_device(monkeypatch)
    def cleanup(path):
        assert path == source
        if raises:
            raise OSError('cleanup denied')
        return False
    monkeypatch.setattr(relocate, 'rmtree_hardened', cleanup)
    assert relocate.move_directory(source, destination) is False
    assert (destination / 'data').read_bytes() == (source / 'data').read_bytes()
    assert str(source) in caplog.text and str(destination) in caplog.text


def test_changed_source_after_copy_is_never_deleted(tree, tmp_path, monkeypatch):
    source, destination = tree
    cross_device(monkeypatch)
    original = shutil.copytree
    saved = tmp_path / 'original'
    def copy(src, dst, **kwargs):
        result = original(src, dst, **kwargs)
        src.rename(saved)
        src.mkdir()
        (src / 'keep').write_text('other owner')
        return result
    from core.testing.module_bindings import patch_module_attribute
    patch_module_attribute(monkeypatch, relocate, 'shutil', 'copytree', copy)
    with pytest.raises(OSError, match='source directory changed'):
        relocate.move_directory(source, destination)
    assert (source / 'keep').read_text() == 'other owner'
    assert (saved / 'data').read_bytes() == b'run data'
    assert not destination.exists()


def test_cross_filesystem_copy_preserves_intra_tree_hardlinks(tree, monkeypatch):
    source, destination = tree
    os.link(source / 'data', source / 'same-data')
    cross_device(monkeypatch)
    assert relocate.move_directory(source, destination)
    assert (destination / 'data').stat().st_ino == (destination / 'same-data').stat().st_ino
    assert (destination / 'data').read_bytes() == b'run data'


def test_missing_destination_parents_are_created_after_overlap_validation(tree):
    source, destination = tree
    nested = destination / 'parent/run'
    assert relocate.move_directory(source, nested)
    assert (nested / 'data').read_bytes() == b'run data'


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_copy_reader_failure_reclaims_partial_outputs_and_keeps_source(tree, tmp_path, monkeypatch, failure):
    source, destination = tree
    cross_device(monkeypatch)
    from core.testing.module_bindings import patch_module_attribute
    def broken(reader, writer, **kwargs):
        writer.write(b'partial')
        raise failure('read failed')
    patch_module_attribute(monkeypatch, relocate, 'shutil', 'copyfileobj', broken)
    # copytree aggregates ordinary IO errors in shutil.Error.
    with pytest.raises(shutil.Error if failure is OSError else failure):
        relocate.move_directory(source, destination)
    assert (source / 'data').read_bytes() == b'run data'
    assert not destination.exists()
    assert not list(tmp_path.glob('.move-*'))


@pytest.mark.parametrize('cross', [False, True], ids=['rename', 'copy'])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_failed_rollback_keeps_published_data_and_primary_error(tree, tmp_path, monkeypatch, caplog, cross, failure):
    source, destination = tree
    original = relocate.publish_new_directory
    def publish(src, dst):
        if cross and src == source:
            raise OSError(errno.EXDEV, 'different filesystems')
        original(src, dst)
        raise failure('primary move failure')
    def restore(*args):
        raise OSError('rollback denied')
    monkeypatch.setattr(relocate, 'publish_new_directory', publish)
    monkeypatch.setattr(relocate, 'rename_without_replace', restore)
    with pytest.raises(failure, match='primary move failure'):
        relocate.move_directory(source, destination)
    assert (destination / 'data').read_bytes() == b'run data'
    assert source.exists() == cross
    assert str(destination) in caplog.text
    assert not list(tmp_path.glob('.move-*'))


@pytest.mark.parametrize('cross', [False, True], ids=['rename', 'copy'])
def test_unknown_published_replacement_is_never_deleted(tree, tmp_path, monkeypatch, cross):
    source, destination = tree
    original = relocate.publish_new_directory
    saved = tmp_path / 'saved'
    def publish(src, dst):
        if cross and src == source:
            raise OSError(errno.EXDEV, 'different filesystems')
        original(src, dst)
        dst.rename(saved)
        dst.mkdir()
        (dst / 'keep').write_text('bystander')
    monkeypatch.setattr(relocate, 'publish_new_directory', publish)
    with pytest.raises(OSError, match='destination changed'):
        relocate.move_directory(source, destination)
    assert (destination / 'keep').read_text() == 'bystander'
    assert (saved / 'data').read_bytes() == b'run data'
    assert source.exists() == cross


@pytest.mark.parametrize('mode', [0o400, 0o600, 0o640, 0o755])
def test_copied_regular_files_keep_modes_and_timestamps(tree, monkeypatch, mode):
    source, destination = tree
    data = source / 'data'
    data.chmod(mode)
    os.utime(data, ns=(1_600_000_000_000_000_000, 1_600_000_001_000_000_000))
    before = data.stat()
    cross_device(monkeypatch)
    assert relocate.move_directory(source, destination)
    after = (destination / 'data').stat()
    assert after.st_mode & 0o777 == mode
    assert after.st_mtime_ns == before.st_mtime_ns


def test_reader_refuses_a_file_replaced_with_a_symlink(tree, tmp_path, monkeypatch):
    source, destination = tree
    outside = tmp_path / 'borrowed'
    outside.write_text('private data')
    saved = tmp_path / 'original-data'
    original = relocate.open_regular_gated
    cross_device(monkeypatch)
    def opened(path, **kwargs):
        path = Path(path)
        if path.name == 'data':
            path.rename(saved)
            path.symlink_to(outside)
        return original(path, **kwargs)
    monkeypatch.setattr(relocate, 'open_regular_gated', opened)
    with pytest.raises(shutil.Error):
        relocate.move_directory(source, destination)
    assert outside.read_text() == 'private data'
    assert saved.read_bytes() == b'run data'
    assert not destination.exists()
    assert not list(tmp_path.glob('.move-*'))
