"""Real nested mounts, bypass attempts and RAPTOR spawn; never call a model."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from core.startup.tests.test_install_guard import _fixture, KERNEL_PYTHON

pytestmark = [pytest.mark.integration, pytest.mark.skipif(
    os.environ.get('RAPTOR_INSTALL_PROTECTION_ACCEPTANCE') != '1',
    reason='explicit installation-protection host acceptance')]


def test_nested_mounts_preserve_installation_protection(tmp_path, require_install_mounts):
    root, script, env = _fixture(tmp_path)
    code = r'''
import ctypes, errno, os, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
# No effective mount capability in the frontend namespace.
assert libc.mount(None, str(root).encode(), None, 4096 | 32, None) == -1
assert ctypes.get_errno() in (errno.EPERM, errno.EACCES)
output = root / 'out'
(output / 'link').symlink_to(root / 'source.py')
for operation in (
    lambda: (output / 'link').write_text('bad'),
    lambda: os.chmod(root / 'source.py', 0o777),
):
    try: operation()
    except OSError as exc: assert exc.errno in (errno.EROFS, errno.EPERM, errno.EACCES)
    else: raise AssertionError('write through an alias/metadata bypass succeeded')
# After rejecting existing hardlinks at startup, new cross-boundary aliases
# must remain blocked. Links inside writable state remain useful.
for state in (output, pathlib.Path(os.environ['TMPDIR'])):
    local = state / 'local-file'
    local.write_text('state')
    os.link(local, state / 'local-hardlink')
    for operation in (
        lambda: os.link(root / 'source.py', state / 'source-alias'),
        lambda: os.link(local, root / 'state-alias'),
        lambda: (root / 'new-symlink').symlink_to(local),
    ):
        try: operation()
        except OSError as exc: assert exc.errno in (errno.EXDEV, errno.EROFS, errno.EPERM, errno.EACCES)
        else: raise AssertionError('created a new alias across the source/state boundary')
mountpoint = output / 'mount'
mountpoint.mkdir()
nested = r"""
import ctypes, errno, os, pathlib, sys
root = pathlib.Path(sys.argv[1]); target = root / 'out/mount'
libc = ctypes.CDLL(None, use_errno=True)
# A legitimate descendant mount still works.
assert libc.mount(b'tmpfs', str(target).encode(), b'tmpfs', 0, b'size=1m') == 0, ctypes.get_errno()
(target / 'ok').write_text('nested')
# A nested privileged mount can expose source under a writable pathname, but
# the inherited read-only flag must survive that new bind mount.
alias = target / 'source-alias'
alias.touch()
if libc.mount(str(root / 'source.py').encode(), str(alias).encode(), None, 4096, None) != 0:
    assert ctypes.get_errno() in (errno.EROFS, errno.EACCES, errno.EPERM)
else:
    try: alias.write_text('bad')
    except OSError as exc: assert exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
    else: raise AssertionError('nested bind alias made protected source writable')
try: os.link(root / 'source.py', target / 'hardlink-alias')
except OSError as exc: assert exc.errno in (errno.EXDEV, errno.EROFS, errno.EPERM, errno.EACCES)
else: raise AssertionError('nested namespace created a cross-mount hardlink')
# Inherited readonly mounts cannot be made writable in a less privileged ns.
assert libc.mount(None, b'/', None, 4096 | 32, None) == -1
assert ctypes.get_errno() in (errno.EPERM, errno.EACCES)
try: (root / 'source.py').write_text('bad')
except OSError as exc: assert exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
else: raise AssertionError('nested namespace modified installation')
"""
result = subprocess.run(['/usr/bin/unshare', '--user', '--map-root-user', '--mount',
                         '--', sys.executable, '-I', '-c', nested, str(root)], capture_output=True, text=True)
assert result.returncode == 0, result.stderr
'''
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', KERNEL_PYTHON, '-I',
                             '-c', code, str(root)], env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert (root / 'source.py').read_text() == 'VALUE = 1\n'


def test_raptor_mount_spawn_still_executes(tmp_path, require_install_mounts):
    root = Path(__file__).resolve().parents[3]
    output = tmp_path / 'output'
    output.mkdir()
    home = tmp_path / 'home'
    home.mkdir()
    env = dict(os.environ, HOME=str(home), TMPDIR=str(output), RAPTOR_OUT_DIR=str(output), RAPTOR_DIR=str(root))
    env.pop('RAPTOR_REGISTRY_HOME', None)
    # The child is trusted acceptance code; import the checkout using RAPTOR_DIR.
    code = r'''
import os, shutil, sys
sys.path.insert(0, os.environ['RAPTOR_DIR'])
from core.sandbox._spawn import run_sandboxed
command = ['/usr/bin/true']
if shutil.which('awk'):
    command = ['/bin/sh', '-c', "awk 'BEGIN { print 42 }'"]
r = run_sandboxed(command, target=os.environ['RAPTOR_OUT_DIR'], output=os.environ['RAPTOR_OUT_DIR'],
                  block_network=True, nproc_limit=1024, limits={}, writable_paths=[os.environ['TMPDIR']],
                  readable_paths=None, allowed_tcp_ports=None, seccomp_profile=None, seccomp_block_udp=False,
                  env=None, cwd=None, timeout=5)
assert r.returncode == 0, r.stderr
if len(command) > 1:
    assert r.stdout.strip() == '42', r.stdout
'''
    result = subprocess.run([sys.executable, '-I', '-S', '-B', str(root / 'core/startup/install_guard.py'),
                             '--', sys.executable, '-I', '-c', code],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_public_untrusted_run_keeps_mount_floor_and_hides_home(tmp_path, require_install_mounts):
    root = Path(__file__).resolve().parents[3]
    home = tmp_path / 'home'
    home.mkdir()
    secret = home / 'private-secret'
    secret.write_text('dummy acceptance secret')
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'input.txt').write_text('fixture')
    output = tmp_path / 'output'
    output.mkdir()
    env = dict(os.environ, HOME=str(home), TMPDIR=str(output),
               RAPTOR_OUT_DIR=str(output), RAPTOR_DIR=str(root))
    for name in ('RAPTOR_REGISTRY_HOME', 'RAPTOR_ALLOW_DEGRADED_UNTRUSTED',
                 'RAPTOR_SANDBOX_FLOOR', 'RAPTOR_SANDBOX_DISABLED'):
        env.pop(name, None)
    code = r'''
import os, pathlib, sys
sys.path.insert(0, os.environ['RAPTOR_DIR'])
from core.sandbox import run_untrusted
from core.sandbox.tiers import untrusted_default_floor, ContainmentTier
assert untrusted_default_floor() == ContainmentTier.MOUNT_NS
probe = """
import pathlib, sys
source, output, secret = map(pathlib.Path, sys.argv[1:])
assert (source / 'input.txt').read_text() == 'fixture'
try: (source / 'input.txt').write_text('changed')
except OSError: pass
else: raise AssertionError('untrusted child modified target')
try: secret.stat()
except FileNotFoundError: pass
else: raise AssertionError('host HOME secret is visible by name')
(output / 'proof.txt').write_text('untrusted child ran')
"""
result = run_untrusted(['/usr/bin/python3', '-I', '-S', '-c', probe, *sys.argv[1:]],
                       target=sys.argv[1], output=sys.argv[2],
                       capture_output=True, text=True, timeout=20)
assert result.returncode == 0, result.stderr
assert result.sandbox_info['containment_tier'] == 'mount-ns', result.sandbox_info
assert result.sandbox_info['containment_floor'] == 'mount-ns', result.sandbox_info
'''
    result = subprocess.run([sys.executable, '-I', '-S', '-B', str(root / 'core/startup/install_guard.py'),
                             '--', sys.executable, '-I', '-c', code, str(target), str(output), str(secret)],
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert (output / 'proof.txt').read_text() == 'untrusted child ran'
    assert (target / 'input.txt').read_text() == 'fixture'
    assert secret.read_text() == 'dummy acceptance secret'


@pytest.mark.parametrize('discovery', ['selected', 'running'])
def test_home_installed_python_tool_retains_untrusted_mount_tier(tmp_path, require_install_mounts, discovery):
    root = Path(__file__).resolve().parents[3]
    home = tmp_path / 'home'
    home.mkdir()
    secret = home / '.aws/credentials'
    secret.parent.mkdir()
    secret.write_text('dummy acceptance secret')
    # Model the operator's HOME-rooted venv without copying any real state.
    subprocess.run(['/usr/bin/python3', '-I', '-m', 'venv', '--without-pip', str(home)],
                   check=True, capture_output=True, timeout=30)
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'input.txt').write_text('fixture')
    output = tmp_path / 'output'
    output.mkdir()
    tool = home / 'bin/local-proof'
    tool.write_text('#!' + str(home / 'bin/python3') + "\n" + r'''
import pathlib, sys
source, output, secret = map(pathlib.Path, sys.argv[1:])
assert (source / 'input.txt').read_text() == 'fixture'
try: secret.stat()
except FileNotFoundError: pass
else: raise AssertionError('tool path grants exposed HOME credentials')
(output / 'proof.txt').write_text('home-installed tool ran')
''')
    tool.chmod(0o755)
    env = dict(os.environ, HOME=str(home), TMPDIR=str(output),
               RAPTOR_OUT_DIR=str(output), RAPTOR_DIR=str(root))
    env.pop('RAPTOR_REGISTRY_HOME', None)
    env.pop('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', None)
    code = r'''
import os, sys
sys.path.insert(0, os.environ['RAPTOR_DIR'])
from core.sandbox import run_untrusted
from core.sandbox.python_paths import python_tool_paths, python_runtime_tool_paths
if sys.argv[-1] == 'running':
    # Model this actual venv's interpreter metadata while keeping the
    # trusted test driver on the RAPTOR environment with its dependencies.
    from types import SimpleNamespace
    from unittest.mock import patch
    home = os.environ['HOME']
    runtime = SimpleNamespace(prefix=home, exec_prefix=home, base_prefix='/usr',
                              base_exec_prefix='/usr', executable=home + '/bin/python3')
    with patch('core.sandbox.python_paths.sys', runtime):
        paths = python_runtime_tool_paths()
else:
    paths = python_tool_paths(sys.argv[1])
assert os.environ['HOME'] not in paths, paths
result = run_untrusted(sys.argv[1:-1], target=sys.argv[2], output=sys.argv[3],
                       tool_paths=paths, capture_output=True, text=True, timeout=20)
assert result.returncode == 0, result.stderr
assert result.sandbox_info['containment_tier'] == 'mount-ns', result.sandbox_info
assert result.sandbox_info['containment_floor'] == 'mount-ns', result.sandbox_info
'''
    result = subprocess.run([sys.executable, '-I', '-S', '-B', str(root / 'core/startup/install_guard.py'),
                             '--', sys.executable, '-I', '-c', code,
                             str(tool), str(target), str(output), str(secret), discovery],
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert (output / 'proof.txt').read_text() == 'home-installed tool ran'
    assert secret.read_text() == 'dummy acceptance secret'


def test_single_file_tool_scan_does_not_expose_home_siblings(tmp_path, require_install_mounts):
    root = Path(__file__).resolve().parents[3]
    home = tmp_path / 'home'
    home.mkdir()
    secret = home / '.aws/credentials'
    secret.parent.mkdir()
    secret.write_text('dummy acceptance secret')
    target = home / 'fixture.py'
    target.write_text('fixture')
    rule = tmp_path / 'rule.yml'
    rule.write_text('rules: []')
    output = tmp_path / 'output'
    output.mkdir()
    env = dict(os.environ, HOME=str(home), TMPDIR=str(output),
               RAPTOR_OUT_DIR=str(output), RAPTOR_DIR=str(root))
    env.pop('RAPTOR_REGISTRY_HOME', None)
    code = r'''
import os, sys
sys.path.insert(0, os.environ['RAPTOR_DIR'])
from packages.semgrep.runner import _default_sandbox_runner
probe = """
import pathlib, sys
source, secret = map(pathlib.Path, sys.argv[1:])
assert source.read_text() == 'fixture'
try: source.write_text('changed')
except OSError: pass
else: raise AssertionError('source file is writable')
try: secret.stat()
except FileNotFoundError: pass
else: raise AssertionError('single-file bind exposed HOME siblings')
print('exact-file isolation works')
"""
from pathlib import Path
runner = _default_sandbox_runner(Path(sys.argv[1]), sys.argv[3])
result = runner(['/usr/bin/python3', '-I', '-S', '-c', probe, sys.argv[1], sys.argv[2]],
                capture_output=True, text=True, timeout=20)
assert result.returncode == 0, result.stderr
assert result.sandbox_info['containment_tier'] == 'mount-ns', result.sandbox_info
assert result.stdout.strip() == 'exact-file isolation works', result.stdout
'''
    result = subprocess.run([sys.executable, '-I', '-S', '-B', str(root / 'core/startup/install_guard.py'),
                             '--', sys.executable, '-I', '-c', code, str(target), str(secret), str(rule)],
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert target.read_text() == 'fixture'
    assert secret.read_text() == 'dummy acceptance secret'


@pytest.mark.slow  # real protected interpreter startup and mount verification
def test_protected_helper_filters_writable_imports_and_keeps_user_dependencies(tmp_path, require_install_mounts):
    import sysconfig
    root = Path(__file__).resolve().parents[3]
    home = tmp_path / 'home'
    home.mkdir()
    output = tmp_path / 'output'
    output.mkdir()
    poison = output / 'poison'
    poison.mkdir()
    marker = output / 'poison-executed'
    (poison / 'fractions.py').write_text(
        'from pathlib import Path\n'
        f'Path({str(marker)!r}).write_text("executed")\n'
        'raise AssertionError("writable module was imported")\n')
    (poison / 'argparse.py').write_text(
        'raise AssertionError("writable bootstrap dependency was imported")\n')
    userbase = tmp_path / 'user-dependencies'
    site_packages = Path(sysconfig.get_path('purelib', scheme='posix_user',
                                            vars={'userbase': str(userbase)}))
    site_packages.mkdir(parents=True)
    (site_packages / 'raptor_protected_dependency.py').write_text('VALUE = 42\n')
    env = dict(os.environ, HOME=str(home), TMPDIR=str(output),
               RAPTOR_OUT_DIR=str(output), RAPTOR_DIR=str(root),
               PYTHONUSERBASE=str(userbase), PYTHONPATH=str(site_packages), _RAPTOR_DEP_CHECK='0')
    env.pop('RAPTOR_REGISTRY_HOME', None)
    code = r'''
import os, pathlib, sys
sys.path.insert(0, os.environ['RAPTOR_DIR'])
sys.path.insert(0, sys.argv[1])
sys.modules.pop('fractions', None)
sys.pycache_prefix = sys.argv[2]
import core.startup.process_init
assert sys.argv[1] not in sys.path, sys.path
assert '' not in sys.path, sys.path
assert sys.pycache_prefix is None
assert sys.dont_write_bytecode
import fractions
assert fractions.Fraction(1, 2).denominator == 2
import raptor_protected_dependency
assert raptor_protected_dependency.VALUE == 42
assert not pathlib.Path(sys.argv[3]).exists(), 'writable code executed'
'''
    result = subprocess.run([sys.executable, '-I', '-S', '-B', str(root / 'core/startup/install_guard.py'),
                             '--', sys.executable, '-c', code, str(poison), str(output / 'cache'), str(marker)],
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize('alias_in_output', [False, True])
def test_existing_bind_alias_cannot_become_writable_state(tmp_path, require_install_mounts, alias_in_output):
    root, script, env = _fixture(tmp_path)
    state = tmp_path / 'state'
    state.mkdir()
    alias = root / 'out' if alias_in_output else state / 'alias'
    alias.mkdir()
    env['TMPDIR'] = str(state)
    code = r'''
import ctypes, os, pathlib, subprocess, sys
root, script, alias = map(pathlib.Path, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
assert libc.mount(str(root / 'core').encode(), str(alias).encode(), None, 4096, None) == 0, ctypes.get_errno()
result = subprocess.run([sys.executable, '-I', '-S', '-B', str(script), '--', '/usr/bin/true'],
                         env=os.environ, capture_output=True, text=True)
assert result.returncode == 126, (result.returncode, result.stderr)
assert 'mount aliases protected code' in result.stderr, result.stderr
'''
    result = subprocess.run(['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--',
                             KERNEL_PYTHON, '-I', '-c', code, str(root), str(script), str(alias)],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr



def test_native_wrapper_needs_no_external_runner(tmp_path, require_install_mounts):
    root, script, env = _fixture(tmp_path)
    env['PATH'] = '/nonexistent'
    code = """
import errno
from pathlib import Path
try: Path('source.py').write_text('bad')
except OSError as exc: assert exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
else: raise AssertionError('cwd retained a writable host mount')
"""
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', KERNEL_PYTHON, '-I', '-c', code],
                            cwd=root, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_launcher_death_kills_the_private_pid_namespace(tmp_path, require_install_mounts):
    import time
    root, script, env = _fixture(tmp_path)
    code = r'''
import os, pathlib, subprocess, sys, time
subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
(pathlib.Path(sys.argv[1]) / 'out/ready').write_text('ready')
time.sleep(60)
'''
    process = subprocess.Popen([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', KERNEL_PYTHON, '-I',
                                '-c', code, str(root)], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    namespace_pidfd = None
    try:
        deadline = time.monotonic() + 5
        while not (root / 'out/ready').exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail(process.communicate()[1])
            time.sleep(0.02)
        assert (root / 'out/ready').exists(), 'protected frontend did not become ready'
        children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
        assert len(children) == 1, children
        init = Path('/proc') / children[0] / 'stat'
        namespace_pidfd = os.pidfd_open(int(children[0]))
        process.kill()
        process.communicate(timeout=3)
        deadline = time.monotonic() + 3
        while init.exists() and time.monotonic() < deadline:
            try:
                if init.read_text().rsplit(')', 1)[1].split()[0] == 'Z':
                    break
            except FileNotFoundError:
                break
            time.sleep(0.02)
        else:
            assert not init.exists(), 'namespace init survived launcher death'
    finally:
        if process.poll() is None:
            process.kill()
        if namespace_pidfd is not None:
            import signal
            try:
                signal.pidfd_send_signal(namespace_pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(namespace_pidfd)
        process.communicate(timeout=3)


@pytest.mark.parametrize('under_output', [False, True])
def test_launcher_metadata_is_sealed_while_scratch_stays_writable(tmp_path, require_install_mounts, under_output):
    from core.security import launch_scratch
    root, script, env = _fixture(tmp_path)
    base = root / 'out' if under_output else tmp_path / 'operator-tmp'
    base.mkdir(exist_ok=True)
    metadata = launch_scratch.allocate(base, os.getpid())
    launch_scratch.prepare_protection(metadata)
    env.update(TMPDIR=str(metadata.parent.parent / 'tmp'), _RAPTOR_LAUNCH_METADATA=str(metadata))
    code = r'''
import errno,json,os,pathlib,sys
metadata=pathlib.Path(sys.argv[1])
scratch=pathlib.Path(os.environ['TMPDIR'])
(scratch/'probe').write_text('ok')
assert os.statvfs(metadata.parent).f_flag & os.ST_RDONLY
for operation in (
    lambda: metadata.write_text('{}'),
    lambda: metadata.unlink(),
    lambda: metadata.rename(metadata.with_name('moved')),
    lambda: os.chmod(metadata,0o666),
    lambda: (metadata.parent/'replacement').write_text('{}'),
):
    try: operation()
    except OSError as exc: assert exc.errno in (errno.EROFS,errno.EPERM,errno.EACCES)
    else: raise AssertionError('modified sealed launch metadata')
'''
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', KERNEL_PYTHON, '-I',
                             '-c', code, str(metadata)], env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert (metadata.parent.parent / 'tmp/probe').read_text() == 'ok'


def test_host_controller_cleans_namespace_scratch_and_seals_control_state(tmp_path, require_install_mounts, monkeypatch):
    from core.security import launch_scratch, scratch_lifecycle
    root, script, env = _fixture(tmp_path)
    registry = tmp_path / 'registry'
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(registry))
    family = tmp_path / 'operator-tmp' / f'raptor-{os.geteuid()}'
    family.mkdir(parents=True, mode=0o700)
    session_root = family / f'session-{os.getpid()}-123'
    session_root.mkdir(mode=0o700)
    metadata = launch_scratch.create(session_root)
    session_id = scratch_lifecycle.register(metadata, os.getpid())
    authorization = launch_scratch.issue(tmp_path / 'authorities', metadata, os.getpid())
    launch_scratch.prepare_protection(metadata)
    control = scratch_lifecycle.registry() / (session_id + '.json')
    env.update(RAPTOR_REGISTRY_HOME=str(registry), TMPDIR=str(session_root / 'tmp'),
               _RAPTOR_LAUNCH_METADATA=str(metadata), _RAPTOR_SCRATCH_AUTH=authorization)
    code = r'''
import errno,os,pathlib,sys
scratch=pathlib.Path(os.environ['TMPDIR'])
(scratch/'probe').write_text('ok')
init_fds = set(os.listdir('/proc/1/fd'))
assert init_fds <= {'0','1','2'}, ('namespace init retained descriptors', sorted(init_fds))
for path in (pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])):
    try: path.write_text('changed')
    except OSError as exc: assert exc.errno in (errno.EROFS,errno.EACCES,errno.EPERM)
    else: raise AssertionError('protected source/control record was writable')
'''
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', KERNEL_PYTHON, '-I', '-c',
                             code, str(root / 'source.py'), str(control)], env=env,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert not session_root.exists(), 'outside controller did not remove ended namespace scratch'
    with scratch_lifecycle.locked(session_id) as (_, value):
        assert value['state'] == 'removed'
        assert value['closure'] == 'pid-namespace'



@pytest.mark.parametrize("configured", [False, True])
def test_normal_home_state_remains_writable_without_config_redirect(tmp_path, require_install_mounts, configured):
    root, script, env = _fixture(tmp_path)
    env.pop('CLAUDE_CONFIG_DIR', None)
    if configured:
        env['CLAUDE_CONFIG_DIR'] = str(Path(env['HOME']) / 'custom-claude')
    env.update(EDITOR='vim', VISUAL='vim -f')
    code = r"""
import os, pathlib, sys
home = pathlib.Path.home()
assert os.environ.get('CLAUDE_CONFIG_DIR', '') == sys.argv[2]
if sys.argv[2]:
    custom = pathlib.Path(sys.argv[2])
    custom.mkdir()
    (custom / '.claude.json').write_text('existing configuration location')
assert os.environ['EDITOR'] == 'vim' and os.environ['VISUAL'] == 'vim -f'
for name in ('.claude.json', '.viminfo'):
    temporary = home / (name + '.tmp')
    temporary.write_text('state')
    temporary.replace(home / name)
    assert (home / name).read_text() == 'state'
ordinary = home / 'ordinary-project'
ordinary.mkdir()
(ordinary / 'source.py').write_text('ordinary source')
try: pathlib.Path(sys.argv[1], 'source.py').write_text('bad')
except OSError: pass
else: raise AssertionError('installation source was writable')
"""
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--frontend', 'claude', '--',
                             sys.executable, '-I', '-c', code, str(root), env.get('CLAUDE_CONFIG_DIR', '')],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('alias_parent', [False, True])
@pytest.mark.parametrize('separate_install', [False, True])
def test_ancestor_rename_cannot_substitute_installation(tmp_path, require_install_mounts, alias_parent, separate_install):
    root, script, env = _fixture(tmp_path / 'source-parent/nested')
    alias = tmp_path / 'parent-alias'
    alias.mkdir()
    attack = r'''
import errno, pathlib, sys
parent = pathlib.Path(sys.argv[1])
try: parent.rename(parent.with_name(parent.name + '-moved'))
except OSError as error: assert error.errno in (errno.EBUSY, errno.EROFS, errno.EPERM, errno.EACCES), error
else: raise AssertionError('installation ancestor was renamed')
'''
    code = r'''
import ctypes, os, pathlib, shutil, subprocess, sys
root, script, alias = map(pathlib.Path, sys.argv[1:4])
libc = ctypes.CDLL(None, use_errno=True)
if sys.argv[6] == 'separate':
    saved = root.with_name('saved-install')
    shutil.copytree(root, saved)
    assert libc.mount(b'tmpfs', str(root).encode(), b'tmpfs', 0, b'size=16m') == 0
    shutil.copytree(saved, root, dirs_exist_ok=True)
if sys.argv[4] == 'alias':
    assert libc.mount(str(root.parent.parent).encode(), str(alias).encode(), None, 4096 | 16384, None) == 0
parent = alias / root.parent.name if sys.argv[4] == 'alias' else root.parent
result = subprocess.run([sys.executable, '-I', '-S', '-B', str(script), '--', sys.executable, '-I', '-c', sys.argv[5], str(parent)],
                        capture_output=True, text=True, env=os.environ)
assert result.returncode == 0, result.stderr
'''
    result = subprocess.run(['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--',
                             KERNEL_PYTHON, '-I', '-c', code, str(root), str(script), str(alias),
                             'alias' if alias_parent else 'canonical', attack,
                             'separate' if separate_install else 'same-filesystem'],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_vim_history_is_writable_without_changing_editor_settings(tmp_path, require_install_mounts):
    import shutil
    executable = shutil.which('vim')
    if executable is None:
        pytest.skip('Vim is not installed')
    root, script, env = _fixture(tmp_path)
    history = Path(env['HOME']) / '.viminfo'
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', executable,
                             '-u', 'NONE', '-n', '-es', '-i', str(history),
                             '-c', 'let @a="protection-history-proof"',
                             '-c', 'wviminfo!', '-c', 'qall!'],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert history.is_file()


def test_existing_external_bind_alias_is_readonly(tmp_path, require_install_mounts):
    root, script, env = _fixture(tmp_path)
    alias = tmp_path / 'code-alias'
    alias.mkdir()
    attack = r'''
import pathlib, sys
p = pathlib.Path(sys.argv[1])
assert p.read_text() == 'VALUE = 1\n'
p.write_text('bad')
'''
    code = r'''
import ctypes, os, pathlib, subprocess, sys
root, script, alias = map(pathlib.Path, sys.argv[1:4])
libc = ctypes.CDLL(None, use_errno=True)
assert libc.mount(str(root).encode(), str(alias).encode(), None, 4096 | 16384, None) == 0
result = subprocess.run([sys.executable, '-I', '-S', '-B', str(script), '--', sys.executable, '-I', '-c', sys.argv[4], str(alias/'source.py')],
                         capture_output=True, text=True, env=os.environ)
assert result.returncode != 0
assert 'Read-only file system' in result.stderr, result.stderr
assert (root/'source.py').read_text() == 'VALUE = 1\n'
'''
    result = subprocess.run(['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--',
                             KERNEL_PYTHON, '-I', '-c', code, str(root), str(script), str(alias), attack],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_nested_python_environment_has_no_writable_parent_holes(tmp_path, require_install_mounts):
    root, script, env = _fixture(tmp_path)
    venv = root / '.venv'
    (venv / 'bin').mkdir(parents=True)
    (venv / 'bin/python3').symlink_to(KERNEL_PYTHON)
    (venv / 'pyvenv.cfg').write_text('home = /usr/bin\n')
    (venv / 'lib/python3.14').mkdir(parents=True)
    env['PATH'] = str(venv/'bin') + os.pathsep + env['PATH']
    code = r'''
import errno, pathlib, sys
root = pathlib.Path(sys.argv[1])
for parent in (root, root/'.venv', root/'.venv/lib', root/'.venv/lib/python3.14'):
    try: (parent/'injected.py').write_text('bad')
    except OSError as error: assert error.errno in (errno.EROFS, errno.EACCES, errno.EPERM), error
    else: raise AssertionError(f'writable hole beneath installation: {parent}')
'''
    result = subprocess.run([KERNEL_PYTHON, '-I', '-S', '-B', str(script), '--', KERNEL_PYTHON,
                             '-I', '-c', code, str(root)], env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
