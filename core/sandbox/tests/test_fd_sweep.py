"""Exec-boundary descriptor sweeps must not rely on rlimits or procfs access."""
from pathlib import Path
import resource
import subprocess
import sys

import pytest

from core.sandbox.tests.capability import requires_landlock

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux descriptor sweep')
ROOT = str(Path(__file__).resolve().parents[3])


def _driver(tmp_path, script, *args):
    result = subprocess.run(
        [sys.executable, '-I', '-S', '-c', script, ROOT, *map(str, args)],
        cwd=tmp_path, capture_output=True, text=True, timeout=45,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    return result


@requires_landlock
@pytest.mark.linux_native
@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize('planted', [300, 70000])
def test_restricted_procfs_and_lowered_hard_limit_do_not_leak_at_exec(tmp_path, planted):
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard <= planted + 1:
        pytest.skip('inherited hard limit cannot accommodate high descriptor fixture')
    secret = tmp_path / 'outside-policy'
    secret.write_bytes(b'owned-secret')
    result = _driver(tmp_path, r'''
import os, resource, sys
sys.path.insert(0, sys.argv[1])
from core.sandbox._spawn import _prepare_exec_fds
from core.sandbox.landlock import _make_landlock_preexec
planted = int(sys.argv[3])
_, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (planted + 2, hard))
source = os.open(sys.argv[2], os.O_RDONLY)
os.dup2(source, planted)
os.dup2(source, planted + 1)
os.close(source)
status_r, status_w = os.pipe()
restrict = _make_landlock_preexec(
    [], readable_paths=[os.path.realpath(sys.base_prefix),
                       os.path.realpath(sys.base_exec_prefix)], fail_raise=True)
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
restrict()
try:
    os.listdir('/proc/self/fd')
except PermissionError:
    pass
else:
    raise AssertionError('test requires actual Landlock procfs denial')
try:
    os.open(sys.argv[2], os.O_RDONLY)
except PermissionError:
    pass
else:
    raise AssertionError('fixture must be outside the read policy')
_prepare_exec_fds((planted + 1,), status_w)
assert not os.get_inheritable(status_w)
probe = """
import errno, os, sys
allowed, ambient, status = map(int, sys.argv[1:])
assert os.read(allowed, 64) == b'owned-secret'
for descriptor in (ambient, status):
    try: os.fstat(descriptor)
    except OSError as exc: assert exc.errno == errno.EBADF
    else: raise AssertionError('undeclared descriptor survived exec')
print('closed ambient and status; preserved declared capability')
"""
os.execv(sys.executable, [sys.executable, '-I', '-S', '-c', probe,
                         str(planted + 1), str(planted), str(status_w)])
''', secret, planted)
    assert result.stdout.strip() == 'closed ambient and status; preserved declared capability'


def test_enumeration_fallback_closes_above_both_limits(tmp_path):
    _driver(tmp_path, r'''
import errno, os, resource, sys
sys.path.insert(0, sys.argv[1])
from core.sandbox import _fd_sweep
_fd_sweep._close_range = None
source = os.open('/dev/null', os.O_RDONLY)
os.dup2(source, 300)
os.close(source)
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
_fd_sweep.close_fds_except(())
try: os.fstat(300)
except OSError as exc: assert exc.errno == errno.EBADF
else: raise AssertionError('enumeration fallback leaked descriptor')
''')


@pytest.mark.parametrize('kernel_failure', ['missing', 'blocked'])
def test_no_safe_sweep_refuses_before_exec(tmp_path, kernel_failure):
    marker = tmp_path / 'target-executed'
    _driver(tmp_path, r'''
import errno, os, sys
sys.path.insert(0, sys.argv[1])
from core.sandbox import _fd_sweep
_fd_sweep._close_range = None if sys.argv[3] == 'missing' else lambda *args: -1
def unavailable(path):
    raise PermissionError(errno.EACCES, 'owned procfs-denial fixture')
_fd_sweep.os.listdir = unavailable
try:
    _fd_sweep.close_fds_except(())
except OSError as exc:
    assert 'refusing exec' in str(exc)
else:
    os.execv('/usr/bin/touch', ['touch', sys.argv[2]])
''', marker, kernel_failure)
    assert not marker.exists()


@requires_landlock
@pytest.mark.linux_native
@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize('audit', [False, True])
def test_native_namespace_sweep_closes_unlisted_high_fd(tmp_path, audit):
    from core.sandbox.tests.capability import pidns_isolation_available
    if not pidns_isolation_available():
        pytest.skip('fresh Linux mount/PID namespaces required')
    work = tmp_path / 'work'
    work.mkdir()
    secret = tmp_path / 'outside-policy'
    secret.write_bytes(b'owned-secret')
    result = _driver(tmp_path, r'''
import os, sys
sys.path.insert(0, sys.argv[1])
from core.sandbox import run
source = os.open(sys.argv[2], os.O_RDONLY)
os.dup2(source, 300)
os.close(source)
probe = """
import errno, os, sys
try: os.listdir('/proc/self/fd')
except PermissionError: pass
else: raise AssertionError('procfs must be outside the read policy')
try: os.open(sys.argv[1], os.O_RDONLY)
except (PermissionError, FileNotFoundError): pass
else: raise AssertionError('fixture must be outside the read policy')
try: os.fstat(300)
except OSError as exc: assert exc.errno == errno.EBADF
else: raise AssertionError('ambient descriptor survived namespace exec')
print('closed ambient descriptor in mount namespace')
"""
result = run(
    ['/usr/bin/python3', '-I', '-S', '-c', probe, sys.argv[2]],
    target=sys.argv[3], output=sys.argv[3], profile='strict',
    omit_proc_reads=True, exclude_tmp_baseline=True, restrict_reads=True,
    fake_home=True, require_fresh_procfs=True, limits={'nofile': 64},
    audit=sys.argv[4] == 'True', capture_output=True, text=True, timeout=30,
)
assert result.returncode == 0, (result.stdout, result.stderr)
assert result.sandbox_info['containment_tier'] == 'mount-ns', result.sandbox_info
print(result.stdout, end='')
''', secret, work, audit)
    assert result.stdout.strip() == 'closed ambient descriptor in mount namespace'
