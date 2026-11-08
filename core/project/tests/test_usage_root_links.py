"""Root files and tree members identify each directory entry consistently."""
import errno
import os
import stat

import pytest

from core.project import disk_usage as disk
from core.testing.module_bindings import patch_module_attribute


BACKENDS = [
    pytest.param(False, id='anchored', marks=pytest.mark.skipif(
        not callable(getattr(os, 'fwalk', None)), reason='requires fwalk')),
    pytest.param(True, id='portable'),
]


def allocated(path):
    info = path.lstat()
    return info.st_blocks * 512 if hasattr(info, 'st_blocks') else info.st_size


@pytest.mark.parametrize('portable', BACKENDS)
@pytest.mark.parametrize('selection', ['files', 'directory-overlap', 'parent-alias'])
@pytest.mark.parametrize('retained', [False, True], ids=['all-selected', 'outside-link'])
@pytest.mark.parametrize('sparse', [False, True], ids=['allocated', 'sparse'])
def test_root_and_tree_links_have_one_identity(tmp_path, monkeypatch, portable, selection, retained, sparse):
    root = tmp_path / 'selected'
    root.mkdir()
    first, second = root / 'first', root / 'second'
    if sparse:
        with first.open('wb') as stream:
            stream.truncate(32 << 20)
    else:
        first.write_bytes(b'x' * 8193)
    os.link(first, second)
    if retained:
        os.link(first, tmp_path / 'retained')
    if selection == 'files':
        roots = [first, second]
        directory_bytes = 0
    else:
        selected_file = first
        if selection == 'parent-alias':
            alias = tmp_path / 'alias'
            alias.symlink_to(root, target_is_directory=True)
            selected_file = alias / 'first'
        roots = [root, selected_file, second]
        directory_bytes = allocated(root)
    if portable:
        patch_module_attribute(monkeypatch, disk, 'os', 'fwalk', None, raising=False)
    sizes, incomplete = disk.estimate_removals(roots + roots[:1])
    assert not incomplete
    assert sum(sizes.values()) == directory_bytes + (0 if retained else allocated(first))
    merged = disk.Usage()
    for path in roots:
        merged.merge(disk.scan_usage(path))
    key = first.stat().st_dev, first.stat().st_ino
    assert len(merged.entries[key].links) == 2
    assert merged.removed_bytes(disk.Usage()) == sum(sizes.values())
    assert merged.reclaimable_bytes == sum(sizes.values())


@pytest.mark.parametrize('retained', [False, True])
def test_equivalent_path_spellings_do_not_invent_an_extra_link(tmp_path, retained):
    root = tmp_path / 'selected'
    root.mkdir()
    first = root / 'data'
    first.write_bytes(b'x' * 8193)
    second = root / '..' / root.name / 'data'
    if retained:
        os.link(first, tmp_path / 'retained')
    sizes, incomplete = disk.estimate_removals([first, second, first])
    assert not incomplete
    assert sum(sizes.values()) == (0 if retained else allocated(first))


@pytest.mark.parametrize('error', [errno.EACCES, errno.EIO, errno.ENOENT])
def test_unavailable_root_parent_identity_is_disclosed_as_incomplete(tmp_path, monkeypatch, error):
    target = tmp_path / 'data'
    target.write_bytes(b'payload')
    calls = []
    class OwnedPath(type(tmp_path)):
        def stat(self, *args, **kwargs):
            if self == tmp_path:
                calls.append(self)
                raise OSError(error, 'parent unavailable')
            return super().stat(*args, **kwargs)
    monkeypatch.setattr(disk, 'Path', OwnedPath)
    usage = disk.scan_usage(target)
    assert calls == [tmp_path]
    assert usage.incomplete and not usage.entries
    assert target.read_bytes() == b'payload'


@pytest.mark.parametrize('kind', ['unknown-inode', 'replaced-parent'])
def test_unverifiable_parent_metadata_never_proves_a_root_link(tmp_path, monkeypatch, kind):
    target = tmp_path / 'data'
    target.write_bytes(b'payload')
    actual = tmp_path.stat()
    class Parent:
        st_ino = 0 if kind == 'unknown-inode' else actual.st_ino
        st_mode = stat.S_IFREG if kind == 'replaced-parent' else actual.st_mode
        st_dev = actual.st_dev
    calls = []
    class OwnedPath(type(tmp_path)):
        def stat(self, *args, **kwargs):
            if self == tmp_path:
                calls.append(self)
                return Parent()
            return super().stat(*args, **kwargs)
    monkeypatch.setattr(disk, 'Path', OwnedPath)
    usage = disk.scan_usage(target)
    assert calls == [tmp_path]
    assert usage.incomplete and not usage.entries
    assert usage.reclaimable_bytes == 0


@pytest.mark.parametrize('failure_type', [KeyboardInterrupt, SystemExit])
def test_parent_identity_probe_propagates_cancellation(tmp_path, monkeypatch, failure_type):
    target = tmp_path / 'data'
    target.write_bytes(b'payload')
    failure = failure_type('cancelled metadata probe')
    class OwnedPath(type(tmp_path)):
        def stat(self, *args, **kwargs):
            if self == tmp_path:
                raise failure
            return super().stat(*args, **kwargs)
    monkeypatch.setattr(disk, 'Path', OwnedPath)
    with pytest.raises(failure_type) as caught:
        disk.scan_usage(target)
    assert caught.value is failure
    assert target.read_bytes() == b'payload'


@pytest.mark.parametrize('spelling', ['direct', 'parent-alias', 'dotted'])
def test_root_and_tree_observations_do_not_invent_removals(tmp_path, spelling):
    root = tmp_path / 'selected'
    root.mkdir()
    target = root / 'data'
    target.write_bytes(b'x' * 8193)
    selected = target
    if spelling == 'parent-alias':
        alias = tmp_path / 'alias'
        alias.symlink_to(root, target_is_directory=True)
        selected = alias / 'data'
    elif spelling == 'dotted':
        selected = root / '..' / root.name / 'data'
    before = disk.scan_usage(selected)
    after = disk.scan_usage(root)
    assert not before.incomplete and not after.incomplete
    assert not before.has_removals(after)
    assert before.removed_bytes(after) == 0


@pytest.mark.parametrize('portable', BACKENDS)
@pytest.mark.parametrize('operation', ['rename', 'move', 'relink'])
@pytest.mark.parametrize('retained', [False, True])
def test_surviving_inode_is_not_credited_as_freed(tmp_path, monkeypatch, portable, operation, retained):
    root = tmp_path / 'selected'
    root.mkdir()
    original = root / 'before'
    original.write_bytes(b'x' * 8193)
    if retained:
        os.link(original, tmp_path / 'retained')
    target = root / 'after'
    if operation == 'move':
        directory = root / 'nested'
        directory.mkdir()
        target = directory / 'after'
    if portable:
        patch_module_attribute(monkeypatch, disk, 'os', 'fwalk', None, raising=False)
    before = disk.scan_usage(root)
    if operation == 'relink':
        os.link(original, target)
        original.unlink()
    else:
        original.rename(target)
    remaining = disk.scan_usage(root)
    assert not before.incomplete and not remaining.incomplete
    assert before.has_removals(remaining)  # A path disappeared; its inode survived.
    assert before.removed_bytes(remaining) == 0
    assert target.read_bytes() == b'x' * 8193
