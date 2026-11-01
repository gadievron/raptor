"""Fail-closed native setup checks; real namespace behavior is host acceptance."""
from pathlib import Path
import os
import sys
from types import SimpleNamespace

import pytest

from core.startup.tests.test_install_guard import guard


@pytest.fixture
def native():
    return guard.native_namespace()


def test_readonly_tree_failure_never_regrants_state(native, monkeypatch):
    binds = []
    monkeypatch.setattr(native, 'mount', lambda *args, **kwargs: binds.append((args, kwargs)))
    monkeypatch.setattr(native, 'minimal_devices', lambda _: None)
    def fail(path, **kwargs):
        if kwargs.get('set_flags', 0) & native.RDONLY:
            raise PermissionError('recursive readonly refused')
    monkeypatch.setattr(native, 'mount_attributes', fail)
    with pytest.raises(PermissionError, match='recursive readonly'):
        native.setup_mounts([(Path('/install/out'), 99)], [], [(Path('/install'), 88)])
    assert not any(args[0] == '/proc/self/fd/99' for args, _ in binds)


def test_only_private_devices_clear_nodev(native, monkeypatch):
    changes = []
    monkeypatch.setattr(native, 'mount', lambda *args, **kwargs: None)
    monkeypatch.setattr(native, 'minimal_devices', lambda _: None)
    monkeypatch.setattr(native, 'mount_attributes', lambda path, **kwargs: changes.append((path, kwargs)))
    monkeypatch.setattr(native.os, 'statvfs', lambda _: SimpleNamespace(f_flag=0))
    native.setup_mounts([(Path('/state'), 99)], [])
    assert changes[0] == ('/', {'set_flags': native.NOSUID | native.NODEV, 'recursive': True})
    assert [path for path, flags in changes if flags.get('clear_flags', 0) & native.NODEV] == ['/dev']
    state = next(flags for path, flags in changes if path == '/state')
    assert state['set_flags'] & native.NODEV
    assert state['clear_flags'] == native.RDONLY


def test_state_is_not_advertised_writable_when_source_is_readonly(native, monkeypatch):
    monkeypatch.setattr(native, 'mount', lambda *args, **kwargs: None)
    monkeypatch.setattr(native, 'minimal_devices', lambda _: None)
    monkeypatch.setattr(native, 'mount_attributes', lambda *args, **kwargs: None)
    monkeypatch.setattr(native.os, 'statvfs', lambda _: SimpleNamespace(f_flag=native.os.ST_RDONLY))
    with pytest.raises(OSError, match='incorrect write policy'):
        native.setup_mounts([(Path('/state'), 99)], [])


def test_parent_death_signal_is_armed_before_pipe_race_check(native, monkeypatch):
    calls = []
    monkeypatch.setattr(native, 'checked', lambda result, operation: calls.append(operation))
    monkeypatch.setattr(native, '_LIBC', SimpleNamespace(prctl=lambda *args: 0))
    monkeypatch.setattr(native.select, 'select', lambda *args: (calls.append('pipe check') or [], [], []))
    native.arm_parent_death(42)
    assert calls == ['arm namespace parent death', 'pipe check']


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux O_PATH state pins')
@pytest.mark.parametrize('symlink', [False, True])
def test_repin_rejects_changed_source_identity_or_symlink(native, tmp_path, symlink):
    path = tmp_path / 'state'
    path.mkdir()
    original = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        path.rename(tmp_path / 'previous')
        if symlink:
            path.symlink_to(tmp_path / 'previous', target_is_directory=True)
        else:
            path.mkdir()
        with pytest.raises(OSError, match='state grant changed'):
            native.repin_current_mount(path, original)
    finally:
        os.close(original)


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux procfs descriptor inspection')
def test_namespace_init_closes_ambient_host_descriptors_before_forking(tmp_path):
    import subprocess
    # Isolate the fork and descriptor sweep from pytest's own files/threads.
    # No namespaces or mount privileges are needed to verify this boundary.
    code = r'''
import errno, importlib.util, os, pathlib, sys
spec = importlib.util.spec_from_file_location('native_install', sys.argv[1])
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
control = os.open(sys.argv[2], os.O_RDONLY)
directory = os.open(sys.argv[3], os.O_RDONLY | os.O_DIRECTORY)
read, write = os.pipe()
def armed(death):
    os.fstat(death)
native.arm_parent_death = armed

def frontend():
    for descriptor in (control, directory, read, write):
        try: os.fstat(descriptor)
        except OSError as error: assert error.errno == errno.EBADF
        else: raise AssertionError('frontend inherited setup descriptor')
    parent_fds = set(os.listdir('/proc/' + str(os.getppid()) + '/fd'))
    assert parent_fds <= {'0', '1', '2'}, parent_fds
    print('descriptor isolation verified', flush=True)
    os._exit(0)
native.namespace_init(read, frontend)
'''
    control = tmp_path / 'host-control'
    control.write_text('must remain outside the protected process tree')
    helper = Path(__file__).resolve().parents[1] / '_install_namespace.py'
    result = subprocess.run([sys.executable, '-I', '-c', code, str(helper), str(control), str(tmp_path)],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'descriptor isolation verified'


def test_install_output_and_metadata_are_mounted_in_hierarchical_order(native, monkeypatch):
    binds = []
    readonly = set()
    monkeypatch.setattr(native, 'minimal_devices', lambda _: None)
    monkeypatch.setattr(native, 'mount', lambda source, destination, *args, **kwargs: binds.append(destination))
    def attributes(path, *, set_flags=0, clear_flags=0, **kwargs):
        if set_flags & native.RDONLY:
            readonly.add(str(path))
        if clear_flags & native.RDONLY:
            readonly.discard(str(path))
    monkeypatch.setattr(native, 'mount_attributes', attributes)
    monkeypatch.setattr(native.os, 'statvfs', lambda path: SimpleNamespace(
        f_flag=native.os.ST_RDONLY if str(path) in readonly else 0))
    native.setup_mounts([(Path('/install/out'), 2)], [],
                        [(Path('/install/out/session/metadata'), 3), (Path('/install'), 1)])
    assert binds[-3:] == ['/install', '/install/out', '/install/out/session/metadata']
    assert '/' not in readonly
    assert '/install' in readonly and '/install/out' not in readonly
    assert '/install/out/session/metadata' in readonly



def test_binding_mounts_preserve_parent_write_policy(native, monkeypatch):
    changes = []
    binds = []
    monkeypatch.setattr(native, 'minimal_devices', lambda _: None)
    monkeypatch.setattr(native, 'mount', lambda *args, **kwargs: binds.append(args))
    monkeypatch.setattr(native, 'mount_attributes', lambda path, **kwargs: changes.append((path, kwargs)))
    native.setup_mounts([], [], [], [(Path('/home/user'), 7)])
    assert ('/proc/self/fd/7', '/home/user') in binds
    assert not any(path == '/home/user' for path, _ in changes)



def test_parent_pins_cannot_reopen_writable_holes_beneath_installation(native, monkeypatch):
    binds = []
    readonly = set()
    monkeypatch.setattr(native, 'minimal_devices', lambda _: None)
    monkeypatch.setattr(native, 'mount', lambda *args, **kwargs: binds.append(args))
    def attributes(path, *, set_flags=0, clear_flags=0, **kwargs):
        if set_flags & native.RDONLY:
            readonly.add(str(path))
    monkeypatch.setattr(native, 'mount_attributes', attributes)
    monkeypatch.setattr(native.os, 'statvfs', lambda path: SimpleNamespace(
        f_flag=native.os.ST_RDONLY if str(path) in readonly else 0))
    native.setup_mounts([], [], [(Path('/install'), 1), (Path('/install/venv/lib/python'), 2)],
                        [(Path('/install/venv/lib'), 3)])
    assert not any(args[0] == '/proc/self/fd/3' for args in binds)
