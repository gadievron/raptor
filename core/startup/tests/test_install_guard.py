"""Outer installation policy: real kernel enforcement, no model calls."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

# Keep kernel checks independent of the host's unrelated tool environment.
KERNEL_PYTHON = '/usr/bin/python3' if Path('/usr/bin/python3').exists() else sys.executable

GUARD = Path(__file__).resolve().parents[1] / 'install_guard.py'
spec = importlib.util.spec_from_file_location('install_guard', GUARD)
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


def test_grants_cannot_cover_code(tmp_path, monkeypatch):
    root = tmp_path / 'install'
    root.mkdir()
    monkeypatch.setattr(guard, 'ROOT', root)
    protected = [root, tmp_path / 'dependencies']
    for path in (tmp_path, root, root / 'core', tmp_path / 'dependencies/cache'):
        with pytest.raises(guard.ProtectionError):
            guard.checked_write_path(path, protected, root / 'out')
    assert guard.checked_write_path(root / 'out', protected, root / 'out') == root / 'out'
    alias = tmp_path / 'alias'
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(guard.ProtectionError):
        guard.checked_write_path(alias / 'core', protected, root / 'out')


def test_precompile_is_hashed_and_refreshes_after_pull(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, 'ROOT', tmp_path)
    source = tmp_path / 'app.py'
    source.write_text('VALUE = 1\n')
    guard.precompile()
    cache = Path(importlib.util.cache_from_source(str(source)))
    initial = cache.read_bytes()
    stamp = cache.stat().st_mtime_ns
    guard.precompile()
    assert cache.stat().st_mtime_ns == stamp
    before = source.stat()
    source.write_text('VALUE = 2\n')
    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
    guard.precompile()
    assert cache.read_bytes() != initial
    assert cache.read_bytes()[4:8] == b'\x03\0\0\0'


def test_precompile_rejects_writable_aliases(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, 'ROOT', tmp_path)
    source = tmp_path / 'app.py'
    source.write_text('VALUE = 1\n')
    alias = tmp_path / 'out'
    alias.mkdir()
    os.link(source, alias / 'app.py')
    with pytest.raises(guard.ProtectionError, match='hard-linked'):
        guard.precompile()


def test_precompile_rejects_cache_symlinks(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, 'ROOT', tmp_path)
    (tmp_path / 'app.py').write_text('VALUE = 1\n')
    output = tmp_path / 'out'
    output.mkdir()
    (tmp_path / '__pycache__').symlink_to(output, target_is_directory=True)
    with pytest.raises(guard.ProtectionError, match='symlinked'):
        guard.precompile()


def test_unavailable_kernel_fails_closed(monkeypatch):
    monkeypatch.setattr(guard.sys, 'platform', 'darwin')
    with pytest.raises(guard.ProtectionError, match='requires Linux'):
        guard.require_platform()


def _fixture(tmp_path):
    root = tmp_path / 'install'
    script = root / 'core/startup/install_guard.py'
    script.parent.mkdir(parents=True)
    shutil.copyfile(GUARD, script)
    shutil.copyfile(GUARD.with_name("_install_namespace.py"), script.with_name("_install_namespace.py"))
    (root / 'core/security').mkdir(parents=True)
    shutil.copyfile(GUARD.parents[1] / 'security/launch_scratch.py', root / 'core/security/launch_scratch.py')
    for module in ('scratch_lifecycle', 'scratch_supervisor', 'cgroup_scope', 'log_sanitisation'):
        shutil.copyfile(GUARD.parents[1] / f'security/{module}.py', root / f'core/security/{module}.py')
    (root / 'source.py').write_text('VALUE = 1\n')
    home = tmp_path / 'home'
    home.mkdir()
    env = {'HOME': str(home), 'PATH': os.environ['PATH'], 'TMPDIR': str(tmp_path / 'scratch')}
    return root, script, env


def test_real_kernel_descendant_cannot_change_installation(tmp_path, require_install_mounts):
    root, script, env = _fixture(tmp_path)
    code = '''
import json, os, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
blocked = []
for action in (
    lambda: (root / 'source.py').write_text('changed'),
    lambda: (root / 'new.py').write_text('injected'),
    lambda: (root / 'source.py').unlink(),
    lambda: (root / 'source.py').rename(root / 'out/moved.py'),
    lambda: os.truncate(root / 'source.py', 0),
    lambda: os.link(root / 'source.py', root / 'out/alias.py'),
):
    try: action()
    except PermissionError: blocked.append(True)
    except OSError as e:
        if e.errno in (18, 30): blocked.append(True)
        else: raise
(root / 'out/result').write_text('ok')
pathlib.Path(os.environ['TMPDIR'], 'scratch').write_text('ok')
with open('/dev/null', 'w') as f: f.write('ok')
child = subprocess.run([sys.executable, '-c', "from pathlib import Path; Path('source.py').write_text('bad')"], cwd=root, capture_output=True)
print(json.dumps({'blocked': len(blocked), 'child': child.returncode}))
'''
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', sys.executable, '-I', '-c', code, str(root)],
                            env=env, capture_output=True, text=True)
    if result.returncode == 126 and ('ABI 3+ is unavailable' in result.stderr or 'requires Linux' in result.stderr):
        assert 'No frontend was started' in result.stderr
        pytest.skip(result.stderr.strip())
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['blocked'] == 6
    assert report['child'] != 0
    assert (root / 'source.py').read_text() == 'VALUE = 1\n'
    assert (root / 'out/result').read_text() == 'ok'




def test_inherited_writable_fd_cannot_bypass_policy(tmp_path, require_install_mounts):
    root, script, env = _fixture(tmp_path)
    with (root / 'source.py').open('r+') as inherited:
        result = subprocess.run(
            [KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', sys.executable, '-I', '-c',
             'import os, sys; os.write(int(sys.argv[1]), b"bad")', str(inherited.fileno())],
            pass_fds=(inherited.fileno(),), env=env, capture_output=True, text=True)
    if result.returncode == 126:
        assert 'No frontend was started' in result.stderr
        if 'ABI 3+ is unavailable' in result.stderr or 'requires Linux' in result.stderr:
            pytest.skip('Landlock unavailable')
        pytest.fail(result.stderr)
    assert result.returncode != 0
    assert 'Bad file descriptor' in result.stderr
    assert (root / 'source.py').read_text() == 'VALUE = 1\n'


def test_precompile_refreshes_a_mismatched_source_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, 'ROOT', tmp_path)
    source = tmp_path / 'app.py'
    source.write_text('VALUE = 1\n')
    guard.precompile()
    cache = Path(importlib.util.cache_from_source(str(source)))
    original = cache.read_bytes()
    cache.write_bytes(original[:8] + b"\0" * 8 + original[16:])
    guard.precompile()
    assert cache.read_bytes() == original


def test_legacy_database_path_changes_only_in_protected_context(tmp_path, monkeypatch):
    from core.config import RaptorConfig
    legacy = tmp_path / 'legacy-dbs'
    monkeypatch.setattr(RaptorConfig, 'CODEQL_DB_DIR', legacy)
    monkeypatch.setenv('RAPTOR_OUT_DIR', str(tmp_path / 'output'))
    monkeypatch.delenv('RAPTOR_INSTALL_PROTECTED', raising=False)
    assert RaptorConfig.get_codeql_db_dir() == legacy
    # Simulate context restoration after config has already been imported.
    monkeypatch.setenv('RAPTOR_INSTALL_PROTECTED', '1')
    assert RaptorConfig.get_codeql_db_dir() == tmp_path / 'output/codeql_dbs'














@pytest.mark.skipif(sys.platform != 'linux', reason='Linux O_PATH grants')
def test_grant_ancestor_swap_cannot_grant_the_installation(tmp_path, monkeypatch):
    root = tmp_path / 'owner/install'
    root.mkdir(parents=True)
    monkeypatch.setattr(guard, 'ROOT', root)
    pivot = tmp_path / 'state/pivot'
    (pivot / 'install').mkdir(parents=True)
    validated = guard.checked_write_path(pivot / 'install', [root], root / 'out')
    pivot.rename(pivot.with_name('previous'))
    pivot.symlink_to(root.parent, target_is_directory=True)
    with pytest.raises(guard.ProtectionError, match='symlink after validation'):
        guard.open_grant(validated, [root])


def test_model_or_profile_name_is_not_a_frontend_identity(tmp_path, require_install_mounts):
    root, script, env = _fixture(tmp_path)
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--',
                             '/usr/bin/true', 'claude'], env=env, capture_output=True, text=True, timeout=10)
    if result.returncode == 126 and ('ABI 3+ is unavailable' in result.stderr or 'requires Linux' in result.stderr):
        pytest.skip(result.stderr.strip())
    assert result.returncode == 0, result.stderr
    assert 'installation protected' not in result.stderr


def test_unused_frontend_settings_do_not_change_write_grants(tmp_path, monkeypatch):
    root = tmp_path / 'install'
    root.mkdir()
    monkeypatch.setattr(guard, 'ROOT', root)
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.setenv('TMPDIR', str(tmp_path / 'scratch'))
    monkeypatch.setenv('CLAUDE_CONFIG_DIR', str(root))
    monkeypatch.setenv('RAPTOR_OUT_DIR', str(root / 'out'))
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    monkeypatch.setenv('XDG_CACHE_HOME', str(tmp_path / 'cache'))
    grants = guard.writable_paths([root], frontend=None)
    assert root not in grants


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='POSIX named pipes')
def test_fifo_bytecode_is_rejected_without_blocking(tmp_path):
    code = '''
import importlib.util, os, pathlib, sys
spec = importlib.util.spec_from_file_location('guard', sys.argv[1])
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
g.ROOT = pathlib.Path(sys.argv[2])
source = g.ROOT / 'app.py'; source.write_text('VALUE = 1\\n')
cache = pathlib.Path(importlib.util.cache_from_source(str(source)))
cache.parent.mkdir(); os.mkfifo(cache)
try: g.precompile()
except g.ProtectionError as e:
    assert 'regular file' in str(e)
else: raise AssertionError('FIFO cache accepted')
'''
    result = subprocess.run([KERNEL_PYTHON, '-I', '-c', code, str(GUARD), str(tmp_path)],
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr













@pytest.mark.skipif(sys.platform != 'linux', reason='Linux O_PATH grants')
def test_descriptor_identity_cannot_alias_a_protected_root(tmp_path, monkeypatch):
    root = tmp_path / 'install'
    root.mkdir()
    monkeypatch.setattr(guard, 'ROOT', root)
    # Emulate a bind-mount alias: a distinct pathname for the same open inode.
    monkeypatch.setattr(guard.os, 'readlink', lambda _: str(tmp_path / 'apparent-state'))
    with pytest.raises(guard.ProtectionError, match='aliases a protected root'):
        guard.open_grant(root, [root])


def test_native_helper_is_loaded_from_the_trusted_installation():
    module = guard.native_namespace()
    assert Path(module.__file__).resolve() == GUARD.with_name('_install_namespace.py')
    assert module.USER == 0x10000000



@pytest.mark.parametrize('alias', ['state', 'install/out'])
def test_mount_alias_to_protected_subtree_is_rejected(tmp_path, monkeypatch, alias):
    root = tmp_path / 'install'
    (root / 'out').mkdir(parents=True)
    state = tmp_path / alias
    state.mkdir(exist_ok=True)
    monkeypatch.setattr(guard, 'ROOT', root)
    text = (f'1 0 8:1 / / rw - ext4 /dev/fake rw\n'
            f'2 1 8:1 {root}/core {state} rw - ext4 /dev/fake rw\n')
    monkeypatch.setattr(guard.Path, 'read_text', lambda *_args, **_kwargs: text)
    with pytest.raises(guard.ProtectionError, match='mount aliases protected'):
        guard.reject_mount_aliases([state], [root])


def test_additional_proc_mount_cannot_expose_host_roots(tmp_path, monkeypatch):
    monkeypatch.setattr(guard.Path, 'read_text', lambda *_args, **_kwargs:
                        '1 0 0:1 / /hostproc ro - proc proc ro\n')
    with pytest.raises(guard.ProtectionError, match='additional host procfs'):
        guard.reject_mount_aliases([], [])


def test_private_stage_cannot_claim_protection_in_normal_process():
    result = subprocess.run([KERNEL_PYTHON, '-I', str(GUARD), '--verify'],
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 126
    assert 'No frontend was started' in result.stderr


def test_pid_namespaces_get_distinct_ledgers_but_share_projects(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.delenv('RAPTOR_REGISTRY_HOME', raising=False)
    guard.prepare_session_registry('claude')
    first = Path(os.environ['RAPTOR_REGISTRY_HOME'])
    monkeypatch.delenv('RAPTOR_REGISTRY_HOME')
    guard.prepare_session_registry('claude')
    second = Path(os.environ['RAPTOR_REGISTRY_HOME'])
    assert first != second
    assert (first / 'projects').resolve() == (second / 'projects').resolve() == tmp_path / '.raptor/projects'


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux procfs descriptor audit')
def test_readonly_stdio_cannot_reopen_host_code(tmp_path):
    root, script, env = _fixture(tmp_path)
    with (root / 'source.py').open('r') as stream:
        result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', '/usr/bin/true'],
                                stdin=stream, env=env, capture_output=True, text=True, timeout=3)
    assert result.returncode == 126
    assert 'refers to protected code' in result.stderr


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux directory descriptors')
def test_stdio_directory_cannot_expose_old_mount_tree(tmp_path):
    root, script, env = _fixture(tmp_path)
    code = r"""
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('guard', sys.argv[1])
guard = importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)
node = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
os.dup2(node, 0)
try: guard.close_inherited_fds([guard.ROOT], guard.ROOT / 'out')
except guard.ProtectionError as exc:
    assert 'directory from the host mount namespace' in str(exc)
else: raise AssertionError('host directory descriptor accepted')
"""
    result = subprocess.run([KERNEL_PYTHON, '-I', '-c', code, str(script), str(root.parent)],
                            env=env, capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr





def test_source_submounts_cannot_hide_writable_bind_aliases(tmp_path, monkeypatch):
    root = tmp_path / 'install'
    (root / 'out').mkdir(parents=True)
    state = tmp_path / 'state'
    state.mkdir()
    monkeypatch.setattr(guard, 'ROOT', root)
    text = (f'1 0 8:1 / / rw - ext4 /dev/fake rw\n'
            f'2 1 8:1 /data/vendor {root}/vendor rw - ext4 /dev/fake rw\n'
            f'3 1 8:1 /data/vendor {state} rw - ext4 /dev/fake rw\n')
    monkeypatch.setattr(guard.Path, 'read_text', lambda *_args, **_kwargs: text)
    with pytest.raises(guard.ProtectionError, match='mount aliases protected'):
        guard.reject_mount_aliases([state], [root])


@pytest.mark.parametrize('path', ['/proc', '/proc/self', '/sys', '/dev', '/dev/pts'])
def test_state_override_cannot_restore_host_proc_or_devices(path, tmp_path):
    with pytest.raises(guard.ProtectionError, match='host virtual filesystem'):
        guard.checked_write_path(Path(path), [tmp_path], tmp_path / 'out')



def test_stdio_cannot_hide_registered_file_handles_in_an_anon_inode(tmp_path, monkeypatch):
    def refuse(message):
        raise guard.ProtectionError(message)
    monkeypatch.setattr(guard, '_reject_stdio', refuse)
    monkeypatch.setattr(guard.os, 'listdir', lambda _: ['0'])
    monkeypatch.setattr(guard.os, 'readlink', lambda _: 'anon_inode:[io_uring]')
    with pytest.raises(guard.ProtectionError, match='anonymous kernel object'):
        guard.close_inherited_fds([tmp_path], tmp_path / 'out')








def test_parallel_bytecode_matches_serial_and_refreshes_changed_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, 'ROOT', tmp_path)
    monkeypatch.setattr(guard.os, 'sched_getaffinity', lambda _: {0, 1})
    for index in range(10):
        (tmp_path / f'module{index}.py').write_text(f'VALUE = {index}\n')
    (tmp_path / 'invalid.py').write_text('not valid python !!!')
    marker = tmp_path / 'must-not-execute'
    (tmp_path / 'noexec.py').write_text(f'from pathlib import Path\nPath({str(marker)!r}).touch()\n')
    guard.precompile()
    assert not marker.exists()
    for index in range(10):
        source = tmp_path / f'module{index}.py'
        cache = Path(importlib.util.cache_from_source(str(source)))
        assert cache.read_bytes() == guard._compile_bytecode(source.read_bytes(), str(source))
    for index in range(10):
        source = tmp_path / f'module{index}.py'
        source.write_text(f'VALUE = {index + 10}\n')
    guard.precompile()
    for index in range(10):
        source = tmp_path / f'module{index}.py'
        cache = Path(importlib.util.cache_from_source(str(source)))
        assert cache.read_bytes() == guard._compile_bytecode(source.read_bytes(), str(source))
    assert not Path(importlib.util.cache_from_source(str(tmp_path / 'invalid.py'))).exists()


@pytest.mark.skipif(sys.platform != 'linux' or not hasattr(os, 'pidfd_open'), reason='Linux worker lifetime')
def test_bytecode_worker_dies_with_its_parent(tmp_path):
    import select
    import signal
    import time
    ready = tmp_path / 'worker-ready'
    code = r"""
import importlib.util, os, pathlib, sys, time
spec = importlib.util.spec_from_file_location('guard', sys.argv[1])
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
parent = os.getpid()
if os.fork() == 0:
    g._bytecode_worker(parent)
    pathlib.Path(sys.argv[2]).write_text(str(os.getpid()))
time.sleep(60)
"""
    parent = subprocess.Popen([sys.executable, '-I', '-c', code, str(GUARD), str(ready)])
    worker = None
    try:
        deadline = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < deadline:
            assert parent.poll() is None
            time.sleep(0.01)
        assert ready.exists(), 'bytecode worker did not initialize'
        worker = os.pidfd_open(int(ready.read_text()))
        parent.kill()
        parent.wait(timeout=3)
        assert select.select([worker], [], [], 3)[0], 'bytecode worker survived launcher death'
    finally:
        if parent.poll() is None:
            parent.kill()
        parent.wait(timeout=3)
        if worker is not None:
            try:
                signal.pidfd_send_signal(worker, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(worker)


def test_bytecode_worker_initialization_failure_stops_preparation(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, 'ROOT', tmp_path)
    monkeypatch.setattr(guard.os, 'sched_getaffinity', lambda _: {0, 1})
    for index in range(9):
        (tmp_path / f'module{index}.py').write_text('VALUE = 1\n')

    def refused(parent):
        raise OSError('parent-death supervision unavailable')

    monkeypatch.setattr(guard, '_bytecode_worker', refused)
    with pytest.raises(guard.ProtectionError, match='bytecode compilation worker failed'):
        guard.precompile()


def test_restricted_worker_ipc_still_performs_full_serial_validation(tmp_path, monkeypatch):
    import concurrent.futures
    monkeypatch.setattr(guard, 'ROOT', tmp_path)
    monkeypatch.setattr(guard.os, 'sched_getaffinity', lambda _: {0, 1})
    for index in range(9):
        (tmp_path / f'module{index}.py').write_text(f'VALUE = {index}\n')

    def unavailable(**kwargs):
        raise PermissionError('IPC resources unavailable')

    monkeypatch.setattr(concurrent.futures, 'ProcessPoolExecutor', unavailable)
    guard.precompile()
    for index in range(9):
        source = tmp_path / f'module{index}.py'
        cache = Path(importlib.util.cache_from_source(str(source)))
        assert cache.read_bytes() == guard._compile_bytecode(source.read_bytes(), str(source))


def test_warm_preparation_reuses_trusted_bytecode_without_compilation(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, 'ROOT', tmp_path)
    source = tmp_path / 'app.py'
    source.write_text('VALUE = 1\n')
    guard.precompile()
    cache = Path(importlib.util.cache_from_source(str(source)))
    stamp = cache.stat().st_mtime_ns

    def unexpected_compile(*args):
        raise AssertionError('unchanged source was recompiled')

    monkeypatch.setattr(guard, '_compile_bytecode', unexpected_compile)
    guard.precompile()
    assert cache.stat().st_mtime_ns == stamp
    before = source.stat()
    source.write_text('VALUE = 2\n')
    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(AssertionError, match='recompiled'):
        guard.precompile()


def test_namespace_cleanup_controller_keeps_the_host_registry_view(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from core.security import launch_scratch, scratch_lifecycle
    registry = tmp_path / 'registry'
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(registry))
    family = tmp_path / f'raptor-{os.geteuid()}'
    family.mkdir(mode=0o700)
    root = family / f'session-{os.getpid()}-123'
    root.mkdir(mode=0o700)
    metadata = launch_scratch.create(root)
    session_id = scratch_lifecycle.register(metadata, os.getpid())
    def child_registry(frontend, **kwargs):
        os.environ['RAPTOR_REGISTRY_HOME'] = str(tmp_path / 'child-only-registry')
    def completed(grants, enter, *, readonly, close_in_child, bindings):
        assert len(close_in_child) == 1
        assert os.getpid() != scratch_lifecycle.scratch()._parent(os.getpid())
        return 7  # Only a protocol test; native acceptance proves the kernel boundary.
    monkeypatch.setattr(guard, 'prepare_session_registry', child_registry)
    monkeypatch.setattr(guard, 'native_namespace', lambda: SimpleNamespace(run=completed))
    status = guard._run_namespace([], [], ['/never-execute'], None,
                                  (scratch_lifecycle, session_id, True))
    assert status == 7
    assert os.environ['RAPTOR_REGISTRY_HOME'] == str(registry)
    assert not root.exists()
    with scratch_lifecycle.locked(session_id) as (_, value):
        assert value['closure'] == 'pid-namespace'
        assert value['state'] == 'removed'


def test_protected_registry_is_owned_scratch_and_preserves_shared_projects(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from core.security import launch_scratch, scratch_lifecycle
    registry = tmp_path / 'operator-registry'
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(registry))
    projects = registry / 'projects'
    projects.mkdir(parents=True)
    sentinel = projects / 'keep.json'
    sentinel.write_text('shared project')
    family = tmp_path / f'raptor-{os.geteuid()}'
    family.mkdir(mode=0o700)
    root = family / f'session-{os.getpid()}-123'
    root.mkdir(mode=0o700)
    metadata = launch_scratch.create(root)
    session_id = scratch_lifecycle.register(metadata, os.getpid())
    receipt = tmp_path / 'registry-location'
    def completed(grants, enter, **kwargs):
        private = Path(os.environ['RAPTOR_REGISTRY_HOME'])
        assert private.is_relative_to(root / 'tmp')
        assert private.joinpath('projects').resolve() == projects
        (private / 'sessions.d').mkdir()
        (private / 'sessions.d/credential').write_text('temporary credential')
        receipt.write_text(str(private))
        return 0
    monkeypatch.setattr(guard, 'native_namespace', lambda: SimpleNamespace(run=completed))
    assert guard._run_namespace([], [], ['/never-execute'], 'claude',
                                (scratch_lifecycle, session_id, True)) == 0
    assert not Path(receipt.read_text()).exists()
    assert sentinel.read_text() == 'shared project'
    assert os.environ['RAPTOR_REGISTRY_HOME'] == str(registry)


def test_missing_namespace_closure_receipt_retains_session(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from core.security import launch_scratch, scratch_lifecycle
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    family = tmp_path / f'raptor-{os.geteuid()}'
    family.mkdir(mode=0o700)
    root = family / f'session-{os.getpid()}-123'
    root.mkdir(mode=0o700)
    metadata = launch_scratch.create(root)
    session_id = scratch_lifecycle.register(metadata, os.getpid())
    def interrupted(*args, **kwargs):
        raise OSError('setup supervisor lost its closure evidence')
    monkeypatch.setattr(guard, 'native_namespace', lambda: SimpleNamespace(run=interrupted))
    assert guard._run_namespace([], [], ['/never-execute'], None,
                                (scratch_lifecycle, session_id, True)) == 126
    assert root.exists()
    with scratch_lifecycle.locked(session_id) as (_, value):
        assert value['state'] == 'retained'
        assert value['closure'] is None


def test_pre_namespace_context_verifies_real_credentials_without_claiming_sealed_mounts(tmp_path, monkeypatch):
    from core.security import launch_scratch, scratch_lifecycle
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    family = tmp_path / f'raptor-{os.geteuid()}'
    family.mkdir(mode=0o700)
    root = family / f'session-{os.getpid()}-123'
    root.mkdir(mode=0o700)
    metadata = launch_scratch.create(root)
    session_id = scratch_lifecycle.register(metadata, os.getpid())
    authorization = launch_scratch.issue(tmp_path / 'authorities', metadata, os.getpid())
    monkeypatch.setenv('_RAPTOR_SCRATCH_AUTH', authorization)
    launch_scratch.prepare_protection(metadata)
    # The guard validates credentials before entering its namespace. Ordinary
    # helper restoration must still refuse this not-yet-sealed metadata.
    with pytest.raises(PermissionError):
        launch_scratch._restore_authorized(authorization)
    _, restored_id, namespace_owned = guard._lifecycle_context(metadata)
    assert restored_id == session_id and namespace_owned
    packet = json.loads(authorization)
    packet['token'] = 'forged'
    monkeypatch.setenv('_RAPTOR_SCRATCH_AUTH', json.dumps(packet))
    with pytest.raises(PermissionError):
        guard._lifecycle_context(metadata)


@pytest.mark.parametrize('name', ['source.py', 'config.json', 'native.so'])
def test_installation_audit_rejects_existing_hardlinks(tmp_path, monkeypatch, name):
    root = tmp_path / 'install'
    root.mkdir()
    source = root / name
    source.write_text('installation')
    os.link(source, tmp_path / 'outside-alias')
    monkeypatch.setattr(guard, 'ROOT', root)
    with pytest.raises(guard.ProtectionError, match='hard-linked installation'):
        guard.audit_protected_paths([root])


def test_external_installation_symlink_target_is_protected(tmp_path, monkeypatch):
    root = tmp_path / 'install'
    root.mkdir()
    external = tmp_path / 'external.py'
    external.write_text('installation')
    (root / 'linked.py').symlink_to(external)
    monkeypatch.setattr(guard, 'ROOT', root)
    assert external in guard.audit_protected_paths([root])


def test_existing_bind_aliases_are_sealed_without_writable_grant(tmp_path, monkeypatch):
    root = tmp_path / 'install'
    root.mkdir()
    alias = tmp_path / 'alias'
    monkeypatch.setattr(guard, 'ROOT', root)
    inventory = (f'1 0 8:1 / / rw - ext4 /dev/fake rw\n'
                 f'2 1 8:1 {root}/core {alias} rw - ext4 /dev/fake rw\n')
    monkeypatch.setattr(guard.Path, 'read_text', lambda *args, **kwargs: inventory)
    assert alias in guard.protected_mount_aliases([root])



def test_ancestor_bindings_include_aliases_on_a_different_install_mount(tmp_path, monkeypatch):
    root = tmp_path / 'home/user/install'
    inventory = (f'1 0 8:1 / / rw - ext4 /dev/home rw\n'
                 f'2 1 8:2 /payload {root} rw - ext4 /dev/install rw\n'
                 f'3 1 8:1 {tmp_path}/home {tmp_path}/alias-home rw - ext4 /dev/home rw\n')
    monkeypatch.setattr(guard.Path, 'read_text', lambda *args, **kwargs: inventory)
    bindings = guard.ancestor_bindings([root])
    assert tmp_path / 'home/user' in bindings
    assert tmp_path / 'alias-home/user' in bindings
    assert Path('/') not in bindings



def test_external_python_environment_is_protected_without_sealing_home(tmp_path, monkeypatch):
    environment = tmp_path / 'python-environment'
    binary = environment / 'bin/python3'
    binary.parent.mkdir(parents=True)
    binary.write_text('not executed')
    (environment / 'pyvenv.cfg').write_text('home = /usr/bin\n')
    libraries = environment / 'lib/python3.14/site-packages'
    libraries.mkdir(parents=True)
    monkeypatch.setattr(guard.shutil, 'which', lambda name: str(binary))
    paths = guard.protected_paths()
    assert binary.parent in paths
    assert environment / 'pyvenv.cfg' in paths
    assert libraries.parent in paths
    assert environment not in paths



@pytest.mark.parametrize('nested', [False, True])
def test_stacked_backing_filesystem_fails_closed(tmp_path, monkeypatch, nested):
    root = tmp_path / 'install'
    root.mkdir()
    text = '1 0 8:1 / / rw - ext4 /dev/fake rw\n' if nested else '1 0 0:1 / / rw - overlay overlay rw\n'
    if nested:
        text += f'2 1 0:2 / {root}/vendor rw - overlay overlay rw\n'
    monkeypatch.setattr(guard, 'ROOT', root)
    monkeypatch.setattr(guard.Path, 'read_text', lambda *args, **kwargs: text)
    with pytest.raises(guard.ProtectionError, match='unsupported installation filesystem'):
        guard.protected_mount_aliases([root])


def test_loop_backing_beneath_a_device_mapper_layer_is_refused(monkeypatch):
    import contextlib
    from types import SimpleNamespace
    @contextlib.contextmanager
    def slaves(path):
        yield iter([SimpleNamespace(path='/sys/devices/virtual/block/loop0')])
    with monkeypatch.context() as patch:
        patch.setattr(guard.os, 'scandir', slaves)
        with pytest.raises(guard.ProtectionError, match='loop-backed'):
            guard.reject_loop_backing('253:12345')


def test_raw_device_stdio_cannot_bypass_file_mounts(monkeypatch):
    def refuse(message):
        raise guard.ProtectionError(message)
    monkeypatch.setattr(guard, '_reject_stdio', refuse)
    import stat
    from types import SimpleNamespace
    original = guard.os.fstat
    with monkeypatch.context() as patch:
        patch.setattr(guard.os, 'listdir', lambda path: ['0'])
        patch.setattr(guard.os, 'readlink', lambda path: '/dev/fake-block')
        patch.setattr(guard.os, 'fstat', lambda fd: SimpleNamespace(st_mode=stat.S_IFBLK) if fd == 0 else original(fd))
        with pytest.raises(guard.ProtectionError, match='raw block device'):
            guard.close_inherited_fds([], Path('/nonexistent'))


@pytest.mark.skipif(sys.platform != 'linux' or not hasattr(os, 'O_TMPFILE'), reason='Linux unnamed files')
@pytest.mark.parametrize('control', [False, True])
@pytest.mark.parametrize('stream', ['stdin', 'stdout', 'stderr'])
def test_unnamed_stdio_alias_is_refused_by_inode_before_frontend(tmp_path, control, stream):
    import ctypes
    import errno
    root, script, env = _fixture(tmp_path)
    if control:
        session = root / 'out' / f'raptor-{os.geteuid()}' / f'session-{os.getpid()}-123'
        session.mkdir(mode=0o700, parents=True)
        target = guard.scratch_metadata().create(session, protected=True)
        content = target.read_bytes()
        env['_RAPTOR_LAUNCH_METADATA'] = str(target)
        env['TMPDIR'] = str(session / 'tmp')
        target.unlink()
    else:
        target = root / 'anonymous.py'
        content = b'VALUE = 2\n'
    try:
        descriptor = os.open(tmp_path, os.O_TMPFILE | os.O_RDWR, 0o600)
    except OSError as error:
        if error.errno in (errno.EOPNOTSUPP, errno.EINVAL):
            pytest.skip('temporary filesystem does not support unnamed files')
        raise
    try:
        os.write(descriptor, content)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        assert libc.linkat(-100, f'/proc/self/fd/{descriptor}'.encode(), -100,
                           os.fsencode(target), 0x400) == 0, ctypes.get_errno()
        assert target.stat().st_nlink == 1
        channels = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE}
        channels[stream] = descriptor
        result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', '/usr/bin/true'],
                                **channels, env=env, text=True, timeout=10)
        assert result.returncode == 126, result.stderr
        if stream != 'stderr':
            assert 'stdio aliases protected installation/control content' in result.stderr
        assert target.read_bytes() == content
    finally:
        os.close(descriptor)


def test_metadata_walk_tolerates_retired_atomic_files_without_skipping_other_entries(tmp_path, monkeypatch):
    import contextlib
    root = tmp_path / 'install'
    root.mkdir()
    retired = root / 'retired.tmp'
    retired.write_text('temporary')
    source = root / 'source.py'
    source.write_text('installation')
    os.link(source, tmp_path / 'alias')
    original = os.scandir
    @contextlib.contextmanager
    def retiring(path):
        with original(path) as entries:
            ordered = sorted(entries, key=lambda entry: entry.name)
            retired.unlink()
            yield iter(ordered)
    monkeypatch.setattr(guard, 'ROOT', root)
    with monkeypatch.context() as patch:
        patch.setattr(guard.os, 'scandir', retiring)
        with pytest.raises(guard.ProtectionError, match='hard-linked installation'):
            guard.audit_protected_paths([root])



def test_refusal_never_reports_into_another_protected_stdio_file(tmp_path):
    root, script, env = _fixture(tmp_path)
    other = root / 'other.py'
    other.write_text('OTHER = 1\n')
    with (root / 'source.py').open('r') as source, other.open('a') as error_output:
        result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', '/usr/bin/true'],
                                stdin=source, stderr=error_output, stdout=subprocess.PIPE,
                                env=env, text=True, timeout=5)
    assert result.returncode == 126
    assert (root / 'source.py').read_text() == 'VALUE = 1\n'
    assert other.read_text() == 'OTHER = 1\n'



def test_output_exception_survives_a_protected_library_ancestor(tmp_path, monkeypatch):
    library = tmp_path / 'library'
    root = library / 'raptor'
    root.mkdir(parents=True)
    monkeypatch.setattr(guard, 'ROOT', root)
    output = root / 'out'
    assert guard.checked_write_path(output / 'result', [root, library], output) == output / 'result'
    with pytest.raises(guard.ProtectionError, match='inside protected code'):
        guard.checked_write_path(root / 'core/new.py', [root, library], output)



def test_final_stdio_validation_preserves_owned_mount_pins(tmp_path):
    source = tmp_path / 'state'
    source.write_text('state')
    code = r"""
import importlib.util, os, pathlib, sys
spec = importlib.util.spec_from_file_location('guard', sys.argv[1])
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
node = os.open(sys.argv[2], os.O_RDONLY)
try:
    guard.close_inherited_fds([], pathlib.Path(sys.argv[2]).parent / 'out', keep_fds=(node,))
    assert os.read(node, 5) == b'state'
finally:
    os.close(node)
"""
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', '-c', code, str(GUARD), str(source)],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr



def test_stacked_parent_cannot_substitute_a_local_install_mount(tmp_path, monkeypatch):
    root = tmp_path / 'install'
    inventory = ('1 0 0:1 / / rw - overlay overlay rw\n'
                 f'2 1 0:2 / {root} rw - tmpfs tmpfs rw\n')
    monkeypatch.setattr(guard.Path, 'read_text', lambda *args, **kwargs: inventory)
    with pytest.raises(guard.ProtectionError, match='unsupported installation filesystem overlay'):
        guard.ancestor_bindings([root])



def test_protection_refuses_to_seal_user_configuration_instead_of_migrating_it(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    root = home / 'raptor'
    root.mkdir()
    monkeypatch.setattr(guard, 'ROOT', root)
    monkeypatch.setenv('HOME', str(home))
    with pytest.raises(guard.ProtectionError, match='user home'):
        guard.validate_user_state([home])
    with pytest.raises(guard.ProtectionError, match='Claude user configuration'):
        guard.validate_user_state([root, home / '.claude'], 'claude')
    guard.validate_user_state([root], 'claude')
    assert not (home / '.claude').exists()
    assert not (home / '.claude.json').exists()
