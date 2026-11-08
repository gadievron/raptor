"""Liveness scans bound enumeration, close iterators and preserve cancellation."""
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import socket
import stat
import tempfile
import time

import pytest

from core.run import tmp_reaper as reaper
from core.testing.module_bindings import patch_module_attribute


def old_root(path):
    path.mkdir()
    now = time.time()
    old = now - 7200
    os.utime(path, (old, old))
    return now, old


@pytest.mark.parametrize('layout', ['flat', 'directories', 'nested'])
def test_activity_budget_bounds_real_enumeration(tmp_path, monkeypatch, layout):
    root = tmp_path / 'candidate'
    now, old = old_root(root)
    parent = root
    paths = [root]
    for index in range(32):
        path = parent / f'entry-{index}'
        if layout in {'directories', 'nested'}:
            path.mkdir()
            if layout == 'nested':
                parent = path
        else:
            path.write_bytes(b'old')
        paths.append(path)
    for path in reversed(paths):
        os.utime(path, (old, old))
    scanned, active, closed = [], [], []
    original = os.scandir
    @contextmanager
    def scan(path):
        assert not active, 'previous directory iterator remained open during descent'
        active.append(path)
        try:
            with original(path) as iterator:
                def entries():
                    for entry in iterator:
                        scanned.append(entry.name)
                        yield entry
                yield entries()
        finally:
            closed.append(active.pop())
    patch_module_attribute(monkeypatch, reaper, 'os', 'scandir', scan)
    monkeypatch.setattr(reaper, '_DEEP_SCAN_MAX_ENTRIES', 1)
    assert reaper._recent_activity(root, now, 3600)
    assert len(scanned) == 2
    assert closed and not active


@pytest.mark.parametrize('mutation', ['symlink', 'directory'])
def test_changed_queued_directory_is_not_traversed(tmp_path, monkeypatch, mutation):
    root = tmp_path / 'candidate'
    now, old = old_root(root)
    child = root / 'child'
    child.mkdir()
    (child / 'owned').write_bytes(b'keep me')
    for path in (child / 'owned', child, root):
        os.utime(path, (old, old))
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'fresh').write_bytes(b'outside data')
    saved = tmp_path / 'saved'
    scans, judged = [], []
    original_scan, original_stat = os.scandir, os.lstat
    @contextmanager
    def scan(path):
        scans.append(path)
        with original_scan(path) as iterator:
            yield iterator
        if path == root:
            child.rename(saved)
            if mutation == 'symlink':
                child.symlink_to(outside, target_is_directory=True)
            else:
                child.mkdir()
                os.utime(child, (old, old))
            # Keep the age prerequisite stable to reach the identity guard.
            os.utime(root, (old, old))
    def lstat(path, *args, **kwargs):
        if path == child:
            judged.append(path)
        return original_stat(path, *args, **kwargs)
    patch_module_attribute(monkeypatch, reaper, 'os', 'scandir', scan)
    patch_module_attribute(monkeypatch, reaper, 'os', 'lstat', lstat)
    assert reaper._recent_activity(root, now, 3600)
    assert judged == [child] and scans == [root]
    assert (saved / 'owned').read_bytes() == b'keep me'
    assert (outside / 'fresh').read_bytes() == b'outside data'


def test_old_symlink_is_metadata_only_not_a_descendant_walk(tmp_path, monkeypatch):
    root = tmp_path / 'candidate'
    now, old = old_root(root)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'fresh').write_bytes(b'fresh outside output')
    link = root / 'link'
    link.symlink_to(outside, target_is_directory=True)
    os.utime(link, (old, old), follow_symlinks=False)
    os.utime(root, (old, old))
    scans = []
    original = os.scandir
    def scan(path):
        scans.append(path)
        return original(path)
    patch_module_attribute(monkeypatch, reaper, 'os', 'scandir', scan)
    assert not reaper._recent_activity(root, now, 3600)
    assert scans == [root]
    assert (outside / 'fresh').read_bytes() == b'fresh outside output'


@pytest.mark.skipif(os.name != 'posix', reason='requires POSIX Unix sockets')
def test_first_live_socket_stops_enumeration_and_closes_scan(monkeypatch):
    with tempfile.TemporaryDirectory(prefix='rpr_', dir='/tmp') as directory:
        root = Path(directory)
        path = root / 'probe.sock'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            with os.scandir(root) as native:
                first = next(native)
            assert stat.S_ISSOCK(first.stat(follow_symlinks=False).st_mode)
            probes, events = [], []
            class Scan:
                yielded = False
                def __enter__(self):
                    events.append('enter')
                    return self
                def __exit__(self, *args):
                    events.append('close')
                def __iter__(self):
                    return self
                def __next__(self):
                    if self.yielded:
                        pytest.fail('liveness scan enumerated past a live socket')
                    self.yielded = True
                    return first
            class OwnedPath(type(root)):
                def iterdir(self):
                    yield path
                    pytest.fail('liveness scan eagerly listed past a live socket')
            patch_module_attribute(monkeypatch, reaper, 'os', 'scandir', lambda _: Scan())
            monkeypatch.setattr(reaper, '_socket_answers', lambda entry: probes.append(entry) or True)
            assert reaper._dir_in_use(OwnedPath(root), set())
            assert probes == [path] and events == ['enter', 'close']


@pytest.mark.parametrize('probe', ['activity', 'sockets'])
@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit, ValueError])
@pytest.mark.parametrize('cleanup_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_scandir_close_preserves_primary_and_releases_iterator(tmp_path, monkeypatch, probe, primary_type, cleanup_type):
    root = tmp_path / 'candidate'
    now, old = old_root(root)
    leaf = root / 'data'
    leaf.write_bytes(b'owned')
    for path in (leaf, root):
        os.utime(path, (old, old))
    primary = primary_type('primary metadata failure')
    cleanup = cleanup_type('secondary scan close failure')
    events = []
    original = os.scandir
    class Entry:
        def __init__(self, entry):
            self.entry = entry
        def __getattr__(self, name):
            return getattr(self.entry, name)
        def stat(self, *, follow_symlinks=True):
            events.append('stat')
            raise primary
    class Scan:
        def __init__(self, path):
            self.native = original(path)
        def __enter__(self):
            events.append('enter')
            return self
        def __exit__(self, *args):
            self.native.close()
            events.append('close')
            raise cleanup
        def __iter__(self):
            return self
        def __next__(self):
            return Entry(next(self.native))
    patch_module_attribute(monkeypatch, reaper, 'os', 'scandir', Scan)
    def exercise():
        return (reaper._recent_activity(root, now, 3600) if probe == 'activity'
                else reaper._dir_in_use(root, set()))
    if primary_type is OSError:
        assert exercise() is True
    else:
        with pytest.raises(primary_type) as caught:
            exercise()
        assert caught.value is primary
    assert events == ['enter', 'stat', 'close']
    assert leaf.read_bytes() == b'owned'


@pytest.mark.parametrize('primary_type', [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_socket_close_preserves_cancellation_and_consumes_descriptor(tmp_path, monkeypatch, primary_type, cleanup_type):
    primary = primary_type('primary socket cancellation')
    cleanup = cleanup_type('secondary socket close failure')
    calls = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as native:
        class Probe:
            def settimeout(self, value):
                native.settimeout(value)
            def connect(self, path):
                calls.append('connect')
                raise primary
            def close(self):
                native.close()
                calls.append('close')
                raise cleanup
        patch_module_attribute(monkeypatch, reaper, 'socket', 'socket', lambda *args: Probe())
        with pytest.raises(primary_type) as caught:
            reaper._socket_answers(tmp_path / 'probe.sock')
        assert caught.value is primary
        assert native.fileno() == -1 and calls == ['connect', 'close']


@pytest.mark.parametrize('error', [errno.ECONNREFUSED, errno.ENOENT, errno.EACCES, errno.EIO])
def test_socket_probe_keeps_refusal_and_ambiguity_distinct(tmp_path, monkeypatch, error):
    calls = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as native:
        class Probe:
            def settimeout(self, value):
                native.settimeout(value)
            def connect(self, path):
                calls.append('connect')
                raise OSError(error, 'owned socket outcome')
            def close(self):
                native.close()
                calls.append('close')
        patch_module_attribute(monkeypatch, reaper, 'socket', 'socket', lambda *args: Probe())
        assert reaper._socket_answers(tmp_path / 'probe.sock') is (error not in {errno.ECONNREFUSED, errno.ENOENT})
        assert native.fileno() == -1 and calls == ['connect', 'close']
