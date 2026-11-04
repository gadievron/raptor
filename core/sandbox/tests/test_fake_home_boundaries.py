"""Parent HOME preparation/staging stays anchored during sibling swaps."""
import errno
import os
from pathlib import Path
import select
import subprocess
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.capability import requires_landlock


@pytest.fixture(autouse=True)
def parent_operations_only(monkeypatch):
    def no_backend(*args, **kwargs):
        pytest.fail('parent filesystem race fixture must not enter sandbox dispatch')

    monkeypatch.setattr(context, 'sandbox', no_backend)


def _exercise(tmp_path, monkeypatch, operation, level, swap):
    output = tmp_path / 'shared'
    home = output / '.home'
    scope = home if level == 'root' else home / ('.config' if operation == 'read' else '.local')
    scope.mkdir(parents=True)
    (scope / 'payload').write_bytes(b'inside')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'payload').write_bytes(b'OUTSIDE-SECRET')
    parked = output / 'parked'
    parked.parent.mkdir(exist_ok=True)
    fired = False
    syscall = os.open if operation == 'read' else os.mkdir
    trigger = 'payload' if operation == 'read' else ('.config' if level == 'root' else 'share')

    def intercepted(path, *args, **kwargs):
        nonlocal fired
        if os.path.basename(path) == trigger and not fired:
            fired = True
            swap(output, scope, parked, outside)
        return syscall(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, 'open' if operation == 'read' else 'mkdir', intercepted)
        if operation == 'read':
            staged = context._stage_fake_home_intake(str(home))
            assert staged is None or b'OUTSIDE-SECRET' not in staged[0].values()
        else:
            try:
                context._prepare_fake_home(str(output))
            except OSError as exc:
                assert exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT)
    assert fired, 'the race hook did not reach the parent syscall boundary'
    assert (outside / 'payload').read_bytes() == b'OUTSIDE-SECRET'
    assert sorted(p.name for p in outside.iterdir()) == ['payload']


def _swap(output, scope, parked, outside):
    scope.rename(parked)
    scope.symlink_to(outside, target_is_directory=True)


@pytest.mark.parametrize('operation', ['read', 'mkdir'])
@pytest.mark.parametrize('level', ['root', 'nested'])
def test_fake_home_parent_operations_resist_directory_swaps(tmp_path, monkeypatch, operation, level):
    _exercise(tmp_path, monkeypatch, operation, level, _swap)


def test_fake_home_staging_refuses_symlinked_root(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'payload').write_bytes(b'outside')
    intake = tmp_path / 'home'
    intake.symlink_to(outside, target_is_directory=True)
    assert context._stage_fake_home_intake(str(intake)) is None


@requires_landlock
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux Landlock sibling')
@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('operation', ['read', 'mkdir'])
@pytest.mark.parametrize('level', ['root', 'nested'])
def test_confined_sibling_cannot_redirect_fake_home_parent(tmp_path, monkeypatch, operation, level):
    def confined_swap(output, scope, parked, outside):
        script = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
from core.sandbox.landlock import _make_landlock_preexec
_make_landlock_preexec([sys.argv[2]], readable_paths=['/usr'], fail_raise=True)()
try: os.open(sys.argv[5] + '/payload', os.O_RDONLY)
except PermissionError: pass
else: raise AssertionError('outside read must be denied to the sibling')
try: os.mkdir(sys.argv[5] + '/forbidden')
except PermissionError: pass
else: raise AssertionError('outside mkdir must be denied to the sibling')
os.rename(sys.argv[3], sys.argv[4])
os.symlink(sys.argv[5], sys.argv[3], target_is_directory=True)
print('swapped', flush=True)
os._exit(0)
'''
        root = str(Path(__file__).resolve().parents[3])
        with subprocess.Popen(
            [sys.executable, '-I', '-S', '-c', script, root, str(output),
             str(scope), str(parked), str(outside)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) as child:
            try:
                ready, _, _ = select.select([child.stdout], [], [], 15)
                assert ready, 'confined sibling swap timed out'
                assert child.stdout.readline() == b'swapped\n', child.stderr.read()
                assert child.wait(timeout=15) == 0, child.stderr.read()
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=15)

    _exercise(tmp_path, monkeypatch, operation, level, confined_swap)
