"""Cache cleanup reports partial I/O failures while continuing other entries."""

import errno
import os
from pathlib import Path
from types import ModuleType

import pytest

from core.sandbox import calibrate as cal, calibrate_cli as cli
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='owned POSIX control filenames')


@pytest.fixture
def owned(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    root = tmp_path / 'cache'
    root.mkdir()
    monkeypatch.setattr(cal, '_CACHE_DIR', root)
    tool = tmp_path / 'tool'
    tool.write_bytes(b'owned binary identity; never executed')
    return root, tool


def seed(root, tool, name, *, other=False):
    profile = cal.SandboxProfile(str(tool), 'other-hash' if other else cal._sha256_file(tool),
                                'env', 'timestamp')
    path = root / name
    path.write_text(profile.to_json())
    return path


def arguments(mode, tool):
    return ['--clear-all'] if mode == 'all' else ['--bin', str(tool), '--clear']


def install_fault(monkeypatch, request, root, bad, stage, error):
    class FaultPath(type(root)):
        def glob(self, pattern, **kwargs):
            if stage == 'glob':
                raise error
            for entry in sorted(Path(self).glob(pattern, **kwargs)):
                yield type(self)(entry)

        def unlink(self, missing_ok=False):
            if self == bad:
                if stage == 'missing':
                    Path(self).unlink()
                    raise FileNotFoundError(errno.ENOENT, 'concurrent removal', str(self))
                if stage == 'unlink':
                    raise error
            return super().unlink(missing_ok=missing_ok)

    monkeypatch.setattr(cal, '_CACHE_DIR', FaultPath(root))
    private = ModuleType('cache_clear_os')
    vars(private).update(vars(os))
    active, bad_fds = set(), set()
    opened, closed = [], []

    def release_if_needed(fd):
        if fd in active:
            os.close(fd)
            active.remove(fd)

    def open_fd(path, *args, **kwargs):
        selected = Path(path) == bad
        if selected and stage == 'open':
            raise error
        fd = os.open(path, *args, **kwargs)
        request.addfinalizer(lambda: release_if_needed(fd))
        active.add(fd)
        opened.append(fd)
        if selected:
            bad_fds.add(fd)
        return fd

    def fstat(fd):
        if fd in bad_fds and stage == 'stat':
            raise error
        return os.fstat(fd)

    def read(fd, count):
        if fd in bad_fds and stage == 'read':
            raise error
        return os.read(fd, count)

    def close(fd):
        selected = fd in bad_fds
        os.close(fd)
        active.remove(fd)
        bad_fds.discard(fd)
        closed.append(fd)
        if selected and stage == 'close':
            raise error

    scan_closed, scan_opened = [], []

    class ScanOwner:
        def __init__(self, iterator):
            self.iterator = iterator
            self.items = None

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.iterator if self.items is None else self.items)

        def __enter__(self):
            try:
                self.items = iter(sorted(self.iterator, key=lambda entry: entry.name))
                return self
            except BaseException:
                self.iterator.close()
                scan_closed.append(True)
                raise

        def __exit__(self, *exc):
            self.iterator.close()
            scan_closed.append(True)

    def scan(path):
        if stage == 'glob':
            raise error
        iterator = os.scandir(path)
        request.addfinalizer(iterator.close)
        scan_opened.append(True)
        return ScanOwner(iterator)

    private.scandir, private.scan_closed, private.scan_opened = scan, scan_closed, scan_opened
    private.open, private.fstat, private.read, private.close = open_fd, fstat, read, close
    monkeypatch.setattr(cal, 'os', private)
    return opened, closed


def assert_failure_output(capsys):
    output = capsys.readouterr()
    assert output.out.startswith('cleared 1 profile(s)')
    assert 'cache operation(s) failed' in output.err
    assert all(c.isprintable() or c == '\n' for c in output.err)
    assert len(output.err) < 1200


@pytest.mark.parametrize('mode', ['all', 'binary'])
@pytest.mark.parametrize('position', ['0', '2'], ids=['failure-first', 'failure-last'])
@pytest.mark.parametrize('code', [errno.EACCES, errno.EIO, errno.EROFS],
                         ids=['permission', 'io', 'read-only'])
def test_unlink_failure_reports_partial_progress(owned, monkeypatch, request, capsys,
                                                mode, position, code):
    root, tool = owned
    bad = seed(root, tool, position + '-' + CONTROL + '.json')
    original = bad.read_bytes()
    healthy = seed(root, tool, '1-healthy.json')
    failure = OSError(code, CONTROL, str(bad))
    opened, closed = install_fault(monkeypatch, request, root, bad, 'unlink', failure)
    result = cli._cli_main(arguments(mode, tool))
    assert bad.read_bytes() == original
    assert not healthy.exists()
    assert opened == closed
    assert cal.os.scan_opened == cal.os.scan_closed
    assert result == 70
    assert_failure_output(capsys)


@pytest.mark.parametrize('stage', ['open', 'stat', 'read', 'close'])
@pytest.mark.parametrize('position', ['0', '2'], ids=['failure-first', 'failure-last'])
def test_binary_cleanup_read_failure_is_reported(owned, monkeypatch, request, capsys,
                                                stage, position):
    root, tool = owned
    bad = seed(root, tool, position + '-' + CONTROL + '.json')
    original = bad.read_bytes()
    healthy = seed(root, tool, '1-healthy.json')
    failure = OSError(errno.EIO, CONTROL, str(bad))
    opened, closed = install_fault(monkeypatch, request, root, bad, stage, failure)
    result = cli._cli_main(arguments('binary', tool))
    assert bad.read_bytes() == original
    assert not healthy.exists()
    assert opened == closed
    assert cal.os.scan_opened == cal.os.scan_closed
    assert result == 70
    assert_failure_output(capsys)


@pytest.mark.parametrize('position', ['0', '2'], ids=['failure-first', 'failure-last'])
def test_clear_all_real_directory_collision_is_reported(owned, capsys, position):
    root, tool = owned
    blocked = root / (position + '-blocked.json')
    blocked.mkdir()
    sentinel = blocked / 'owned-sentinel'
    sentinel.write_bytes(b'preserve')
    healthy = seed(root, tool, '1-healthy.json')
    result = cli._cli_main(['--clear-all'])
    assert sentinel.read_bytes() == b'preserve'
    assert not healthy.exists()
    assert result == 70
    assert_failure_output(capsys)


@pytest.mark.parametrize('mode', ['all', 'binary'])
def test_listing_failure_is_an_operational_exit(owned, monkeypatch, request, capsys, mode):
    root, tool = owned
    bad = seed(root, tool, 'entry.json')
    original = bad.read_bytes()
    install_fault(monkeypatch, request, root, bad, 'glob', OSError(errno.EIO, CONTROL))
    assert cli._cli_main(arguments(mode, tool)) == 70
    assert bad.read_bytes() == original
    output = capsys.readouterr()
    assert output.out == ''
    assert 'raptor-sandbox-calibrate:' in output.err
    assert all(c.isprintable() or c == '\n' for c in output.err)


@pytest.mark.parametrize('mode', ['all', 'binary'])
def test_default_library_keeps_best_effort_count(owned, monkeypatch, request, mode):
    root, tool = owned
    bad = seed(root, tool, '0-bad.json')
    healthy = seed(root, tool, '1-healthy.json')
    install_fault(monkeypatch, request, root, bad, 'unlink', OSError(errno.EACCES, 'owned failure'))
    assert cal.clear_cache(None if mode == 'all' else tool) == 1
    assert bad.exists() and not healthy.exists()


@pytest.mark.parametrize('mode', ['all', 'binary'])
def test_missing_entry_race_stays_successful(owned, monkeypatch, request, capsys, mode):
    root, tool = owned
    bad = seed(root, tool, '0-raced.json')
    healthy = seed(root, tool, '1-healthy.json')
    install_fault(monkeypatch, request, root, bad, 'missing', OSError('unused'))
    assert cli._cli_main(arguments(mode, tool)) == 0
    assert not bad.exists() and not healthy.exists()
    output = capsys.readouterr()
    assert output.out.startswith('cleared 1 profile(s)') and not output.err


@pytest.mark.parametrize('mode', ['all', 'binary'])
def test_invalid_and_other_binary_profiles_keep_existing_selection(owned, capsys, mode):
    root, tool = owned
    healthy = seed(root, tool, 'matching.json')
    other = seed(root, tool, 'other.json', other=True)
    corrupt = root / 'invalid.json'
    corrupt.write_bytes(b'invalid json')
    hidden = seed(root, tool, '.hidden.json')
    uppercase = seed(root, tool, 'uppercase.JSON')
    note = root / 'not-json'
    note.write_bytes(b'preserve')
    assert cli._cli_main(arguments(mode, tool)) == 0
    assert not healthy.exists() and not hidden.exists()
    assert uppercase.exists() and note.read_bytes() == b'preserve'
    assert other.exists() is (mode == 'binary')
    assert corrupt.exists() is (mode == 'binary')
    output = capsys.readouterr()
    assert output.out.startswith('cleared 4' if mode == 'all' else 'cleared 2')
    assert output.err == ''


@pytest.mark.parametrize('mode', ['all', 'binary'])
def test_empty_cache_stays_successful(owned, capsys, mode):
    _root, tool = owned
    assert cli._cli_main(arguments(mode, tool)) == 0
    output = capsys.readouterr()
    assert output.out.startswith('cleared 0 profile(s)') and not output.err


@pytest.mark.parametrize('mode', ['all', 'binary'])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit], ids=['interrupt', 'exit'])
def test_cleanup_keeps_cancellation_authoritative(owned, monkeypatch, request, mode, error_type):
    root, tool = owned
    bad = seed(root, tool, '0-bad.json')
    primary = error_type('owned cancellation')
    install_fault(monkeypatch, request, root, bad, 'unlink', primary)
    with pytest.raises(error_type) as caught:
        cli._cli_main(arguments(mode, tool))
    assert caught.value is primary
    assert cal.os.scan_opened == cal.os.scan_closed
    assert bad.exists()


@pytest.mark.parametrize('mode', ['all', 'binary'])
def test_non_directory_cache_is_not_reported_as_empty(owned, capsys, mode):
    root, tool = owned
    root.rmdir()
    root.write_bytes(b'owned non-directory sentinel')
    result = cli._cli_main(arguments(mode, tool))
    assert root.read_bytes() == b'owned non-directory sentinel'
    assert result == 70
    output = capsys.readouterr()
    assert output.out == ''
    assert 'raptor-sandbox-calibrate:' in output.err


@pytest.mark.parametrize('mode', ['all', 'binary'])
def test_unreadable_cache_is_not_reported_as_empty(owned, request, capsys, mode):
    root, tool = owned
    path = seed(root, tool, 'entry.json')
    original = path.read_bytes()
    previous = root.stat().st_mode & 0o777
    request.addfinalizer(lambda: root.chmod(previous))
    try:
        root.chmod(0)
        try:
            with os.scandir(root):
                pass
        except PermissionError:
            pass
        else:
            pytest.skip('account can bypass owned directory read permissions')
        result = cli._cli_main(arguments(mode, tool))
    finally:
        root.chmod(previous)
    assert path.read_bytes() == original
    assert result == 70
    output = capsys.readouterr()
    assert output.out == ''
    assert 'raptor-sandbox-calibrate:' in output.err


@pytest.mark.parametrize('mode', ['all', 'binary'])
def test_missing_cache_stays_successful(owned, capsys, mode):
    root, tool = owned
    root.rmdir()
    assert cli._cli_main(arguments(mode, tool)) == 0
    output = capsys.readouterr()
    assert output.out.startswith('cleared 0 profile(s)') and not output.err
