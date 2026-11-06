"""Exclusive directory publication preserves every contender and complete tree."""

import ctypes
import errno
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace
import sys

import pytest

from core.atomic_fs import publish_new_directory
from core.atomic_fs import directory


@pytest.fixture
def tree(tmp_path):
    source = tmp_path / 'source'
    (source / 'nested').mkdir(parents=True)
    (source / 'nested/payload').write_bytes(b'complete tree')
    return source, tmp_path / 'destination'


def native_only():
    if sys.platform not in ('linux', 'darwin'):
        pytest.skip('native exclusive directory rename requires Linux or macOS')


def test_native_publication_moves_complete_tree_without_copy(tree):
    native_only()
    source, target = tree
    before = source.stat()
    publish_new_directory(source, target)
    assert not source.exists()
    assert (target.stat().st_dev, target.stat().st_ino) == (before.st_dev, before.st_ino)
    assert (target / 'nested/payload').read_bytes() == b'complete tree'


@pytest.mark.parametrize('kind', ['empty-directory', 'nonempty-directory', 'file', 'symlink', 'dangling'])
def test_native_publication_refuses_every_occupied_name(tree, tmp_path, kind):
    native_only()
    source, target = tree
    outside = tmp_path / 'operator'
    outside.mkdir()
    (outside / 'keep').write_text('operator')
    if kind.endswith('directory'):
        target.mkdir()
        if kind == 'nonempty-directory':
            (target / 'keep').write_text('operator')
    elif kind == 'file':
        target.write_text('operator')
    else:
        target.symlink_to(outside if kind == 'symlink' else tmp_path / 'absent', target_is_directory=True)
    before = target.lstat()
    with pytest.raises(FileExistsError):
        publish_new_directory(source, target)
    after = target.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (before.st_dev, before.st_ino, before.st_mode)
    assert (source / 'nested/payload').read_bytes() == b'complete tree'
    assert (outside / 'keep').read_text() == 'operator'


def test_native_competing_publishers_have_exactly_one_winner(tmp_path):
    native_only()
    sources = [tmp_path / 'first', tmp_path / 'second']
    for index, source in enumerate(sources):
        source.mkdir()
        (source / 'payload').write_text(str(index))
    target = tmp_path / 'published'
    ready = Barrier(2)

    def publish(index):
        ready.wait(timeout=10)
        try:
            publish_new_directory(sources[index], target)
        except FileExistsError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(publish, index) for index in range(2)]
        outcomes = [future.result(timeout=15) for future in pending]
    assert outcomes.count(True) == 1
    winner = outcomes.index(True)
    assert (target / 'payload').read_text() == str(winner)
    assert not sources[winner].exists()
    assert (sources[1 - winner] / 'payload').read_text() == str(1 - winner)


@pytest.mark.parametrize('kind', ['file', 'symlink', 'missing', 'same-name'])
def test_invalid_source_or_same_name_never_calls_native_operation(tree, monkeypatch, tmp_path, kind):
    source, target = tree
    if kind == 'file':
        source = source / 'nested/payload'
    elif kind == 'symlink':
        link = tmp_path / 'link'
        link.symlink_to(source, target_is_directory=True)
        source = link
    elif kind == 'missing':
        source = tmp_path / 'absent'
    else:
        target = source
    monkeypatch.setattr(directory, '_rename_without_replace', lambda *args: pytest.fail('invalid publication reached native operation'))
    with pytest.raises(OSError):
        publish_new_directory(source, target)


@pytest.mark.parametrize('which', ['source', 'destination'])
def test_nul_is_rejected_before_native_call(tree, monkeypatch, which):
    source, target = tree
    source = str(source) + '\0suffix' if which == 'source' else source
    target = str(target) + '\0suffix' if which == 'destination' else target
    monkeypatch.setattr(directory, '_rename_without_replace', lambda *args: pytest.fail('NUL reached C string conversion'))
    with pytest.raises(ValueError, match='null byte'):
        publish_new_directory(source, target)


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
@pytest.mark.parametrize('error', [0, errno.EEXIST, errno.EXDEV, errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL])
def test_native_adapter_uses_exclusive_flags_and_never_falls_back(tree, monkeypatch, platform, error):
    source, target = tree
    calls = []

    class Operation:
        def __call__(self, *args):
            calls.append(args)
            ctypes.set_errno(error)
            return -1 if error else 0

    operation = Operation()
    library = SimpleNamespace(**{'renameat2' if platform == 'linux' else 'renamex_np': operation})
    monkeypatch.setattr(directory, 'sys', SimpleNamespace(platform=platform))
    monkeypatch.setattr(directory, 'ctypes', SimpleNamespace(**{**vars(ctypes), 'CDLL': lambda *a, **kw: library}))
    if error:
        with pytest.raises(OSError) as caught:
            publish_new_directory(source, target)
        assert caught.value.errno == error
        assert (source / 'nested/payload').read_bytes() == b'complete tree'
        assert not target.exists()
    else:
        publish_new_directory(source, target)
    expected = (os.fsencode(source), os.fsencode(target), 4)
    if platform == 'linux':
        expected = (-100, os.fsencode(source), -100, os.fsencode(target), 1)
    assert calls == [expected]
    assert operation.restype is ctypes.c_int
    assert len(operation.argtypes) == len(expected)


@pytest.mark.parametrize('platform', ['linux', 'darwin', 'unsupported'])
def test_missing_native_api_refuses_without_mutating_either_path(tree, monkeypatch, platform):
    source, target = tree
    monkeypatch.setattr(directory, 'sys', SimpleNamespace(platform=platform))
    monkeypatch.setattr(directory, 'ctypes', SimpleNamespace(**{**vars(ctypes), 'CDLL': lambda *a, **kw: SimpleNamespace()}))
    with pytest.raises(OSError) as caught:
        publish_new_directory(source, target)
    assert caught.value.errno == errno.ENOTSUP
    assert source.is_dir() and not target.exists()
