"""Cache orphan admission follows compact atomic-writer names."""
from contextlib import contextmanager
import os
import threading
import time

import pytest

from core import atomic_fs
from core.atomic_fs import _atomic_temporary_name
from core.json.cache import JsonCache
from core.json import cache
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('wide', [False, True], ids=['ascii', 'multibyte'])
@pytest.mark.parametrize('nonce', ['01234567', '0123456789abcdef'])
@pytest.mark.parametrize('kind', ['old', 'fresh', 'symlink', 'directory', 'fifo'])
def test_compact_writer_orphans_respect_age_and_node_type(tmp_path, wide, nonce, kind):
    root = tmp_path / 'cache'
    root.mkdir()
    limit = os.pathconf(root, 'PC_NAME_MAX')
    name = ('é' * ((limit - 5) // 2) if wide else 'x' * (limit - 5)) + '.json'
    temporary = _atomic_temporary_name(name, '.atomic-', nonce, root)
    assert len(os.fsencode(temporary)) <= limit
    assert temporary.count('.') == 3, temporary
    path = root / temporary
    target = tmp_path / 'borrowed'
    target.write_bytes(b'preserve target')
    if kind == 'symlink':
        path.symlink_to(target)
    elif kind == 'directory':
        path.mkdir()
    elif kind == 'fifo':
        os.mkfifo(path)
    else:
        path.write_bytes(b'owned staging content')
    if kind != 'fresh':
        old = time.time() - 7200
        os.utime(path, (old, old), follow_symlinks=False)
    before = path.lstat()
    target_before = target.stat()
    JsonCache(root)
    if kind == 'old':
        assert not path.exists()
    else:
        assert path.lstat().st_ino == before.st_ino
    assert target.read_bytes() == b'preserve target'
    assert target.stat().st_mtime_ns == target_before.st_mtime_ns


@pytest.mark.parametrize('body', [
    'a' * 15 + '.' + 'b' * 8,
    'a' * 17 + '.' + 'b' * 8,
    'A' * 16 + '.' + 'b' * 8,
    'g' * 16 + '.' + 'b' * 8,
    'a' * 16 + '.' + 'b' * 7,
    'a' * 16 + '.' + 'b' * 9,
    'a' * 16 + '.' + 'b' * 15,
    'a' * 16 + '.' + 'b' * 17,
    'a' * 16 + '.' + 'B' * 8,
    'a' * 16 + '.' + 'g' * 8,
    'a' * 16 + '.' + 'b' * 8 + '.extra',
])
def test_compact_near_shapes_remain_caller_owned(tmp_path, body):
    path = tmp_path / ('.atomic-' + body + '.tmp')
    path.write_bytes(b'caller owned')
    old = time.time() - 7200
    os.utime(path, (old, old))
    before = path.stat()
    JsonCache(tmp_path)
    assert path.read_bytes() == b'caller owned'
    assert path.stat().st_ino == before.st_ino


def test_incomplete_walk_does_not_publish_success_marker(tmp_path, monkeypatch):
    child = tmp_path / 'child'
    child.mkdir()
    top = tmp_path / 'top.tmp.123'
    nested = child / 'nested.tmp.123'
    for path in (top, nested):
        path.write_bytes(b'owned orphan')
        old = time.time() - 7200
        os.utime(path, (old, old))
    original = cache.os.scandir
    calls = []

    def deny_child(path):
        if os.fspath(path) == str(child):
            calls.append(path)
            raise PermissionError('owned child traversal failure')
        return original(path)

    with monkeypatch.context() as scope:
        patch_module_attribute(scope, cache, 'os', 'scandir', deny_child)
        cache.JsonCache(tmp_path)
    assert calls
    assert not top.exists()
    assert nested.exists()
    assert not (tmp_path / cache._REAP_SENTINEL_NAME).exists()
    cache.JsonCache(tmp_path)
    assert not nested.exists()


def test_unavailable_entry_type_does_not_publish_success_marker(tmp_path, monkeypatch):
    child = tmp_path / 'child'
    child.mkdir()
    nested = child / 'nested.tmp.123'
    nested.write_bytes(b'owned orphan')
    old = time.time() - 7200
    os.utime(nested, (old, old))
    original = cache.os.scandir
    reached = []

    class UnavailableDirectory:
        def __init__(self, entry):
            self.entry = entry

        def __getattr__(self, name):
            return getattr(self.entry, name)

        def is_dir(self, *, follow_symlinks=True):
            reached.append(self.entry.path)
            raise PermissionError('owned entry classification failure')

    @contextmanager
    def unavailable_type(path):
        with original(path) as entries:
            yield (UnavailableDirectory(entry) if entry.path == str(child) else entry
                   for entry in entries)

    with monkeypatch.context() as scope:
        patch_module_attribute(scope, cache, 'os', 'scandir', unavailable_type)
        cache.JsonCache(tmp_path)
    assert reached == [str(child)]
    assert nested.exists()
    assert not (tmp_path / cache._REAP_SENTINEL_NAME).exists()
    cache.JsonCache(tmp_path)
    assert not nested.exists()


@pytest.mark.parametrize('phase', ['inspect', 'recheck', 'unlink'])
def test_candidate_errors_withhold_success_until_a_completed_retry(tmp_path, monkeypatch, phase):
    path = tmp_path / 'entry.tmp.123'
    path.write_bytes(b'owned old staging content')
    old = time.time() - 7200
    os.utime(path, (old, old))
    calls = []

    class Candidate(type(path)):
        def lstat(self):
            calls.append(None)
            if (phase == 'inspect' and len(calls) == 1
                    or phase == 'recheck' and len(calls) == 2):
                raise PermissionError('owned candidate inspection failure')
            return super().lstat()

        def unlink(self, *args, **kwargs):
            raise PermissionError('owned candidate deletion failure')

    with monkeypatch.context() as scope:
        scope.setattr(cache, '_iter_tempfile_candidates', lambda *a, **kw: iter([Candidate(path)]))
        cache.JsonCache(tmp_path)
    assert path.exists()
    assert not (tmp_path / cache._REAP_SENTINEL_NAME).exists()
    cache.JsonCache(tmp_path)
    assert not path.exists()
    assert (tmp_path / cache._REAP_SENTINEL_NAME).is_file()


def test_concurrently_removed_candidate_does_not_prevent_success_marker(tmp_path, monkeypatch):
    path = tmp_path / 'already-removed.tmp.123'
    assert not path.exists()
    monkeypatch.setattr(cache, '_iter_tempfile_candidates', lambda *a, **kw: iter([path]))
    cache.JsonCache(tmp_path)
    assert (tmp_path / cache._REAP_SENTINEL_NAME).is_file()


def test_active_compact_writer_retains_its_staging_file(tmp_path, monkeypatch):
    root = tmp_path / 'cache'
    root.mkdir()
    limit = os.pathconf(root, 'PC_NAME_MAX')
    destination = root / ('x' * (limit - 5) + '.json')
    entered, release = threading.Event(), threading.Event()
    staging, failures = [], []
    original = atomic_fs.os.replace

    def publish(source, target, **kwargs):
        if target == destination:
            staging.append(source)
            entered.set()
            assert release.wait(5), 'writer publication was not released'
        return original(source, target, **kwargs)

    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'replace', publish)

    def write():
        try:
            atomic_fs.write_bytes_atomically(destination, b'{"value":1}')
        except BaseException as error:
            failures.append(error)

    writer = threading.Thread(target=write)
    try:
        writer.start()
        assert entered.wait(5), failures
        assert staging[0].name.count('.') == 3
        assert staging[0].exists()
        cache.JsonCache(root)
        assert staging[0].exists(), 'cleanup removed an active writer staging file'
    finally:
        release.set()
        if writer.ident is not None:
            writer.join(5)
    assert not writer.is_alive()
    assert not failures, failures
    assert destination.read_bytes() == b'{"value":1}'
    assert not staging[0].exists()
