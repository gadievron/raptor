"""The unrestricted parent must not follow a sibling's cleanup-time links."""
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys

import pytest

from core.sandbox import _spawn
from core.sandbox.tests.capability import requires_landlock

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux spawn cleanup')


def test_cleanup_removes_nested_files_without_following_links(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    marker = outside / 'payload'
    marker.write_text('keep')
    stub = tmp_path / 'stub'
    (stub / 'nested').mkdir(parents=True)
    (stub / 'nested/payload').write_text('discard')
    (stub / 'link').symlink_to(outside, target_is_directory=True)
    _spawn._cleanup_stub(str(stub))
    assert marker.read_text() == 'keep'
    if shutil.rmtree.avoids_symlink_attacks:
        assert not stub.exists()


def test_cleanup_leaves_top_level_symlink_untouched(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    marker = outside / 'payload'
    marker.write_text('keep')
    stub = tmp_path / 'stub'
    stub.symlink_to(outside, target_is_directory=True)
    _spawn._cleanup_stub(str(stub))
    assert stub.is_symlink()
    assert marker.read_text() == 'keep'


def test_cleanup_refuses_unsafe_recursive_implementation(tmp_path, monkeypatch):
    stub = tmp_path / 'stub'
    stub.mkdir()
    marker = stub / 'payload'
    marker.write_text('leave')

    def unsafe(*args, **kwargs):
        pytest.fail('unsafe recursive cleanup was called')

    unsafe.avoids_symlink_attacks = False
    monkeypatch.setattr(shutil, 'rmtree', unsafe)
    _spawn._cleanup_stub(str(stub))
    assert marker.read_text() == 'leave'
    empty = tmp_path / 'empty'
    empty.mkdir()
    _spawn._cleanup_stub(str(empty))
    assert not empty.exists()


def _line(stream):
    ready, _, _ = select.select([stream], [], [], 10)
    assert ready, 'confined sibling handshake timed out'
    return stream.readline()


@requires_landlock
@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('swap', ['root', 'nested'])
def test_confined_sibling_cannot_redirect_parent_cleanup(tmp_path, monkeypatch, swap):
    if not shutil.rmtree.avoids_symlink_attacks:
        pytest.skip('descriptor-based recursive cleanup required for race exercise')
    shared = tmp_path / 'shared'
    stub = shared / 'stub'
    scope = stub if swap == 'root' else stub / 'nested'
    scope.mkdir(parents=True)
    (scope / 'payload').write_text('discard')
    outside = tmp_path / 'outside'
    outside.mkdir()
    marker = outside / 'payload'
    marker.write_text('keep')
    parked = shared / 'parked'
    script = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
from core.sandbox.landlock import _make_landlock_preexec
_make_landlock_preexec([sys.argv[2]], readable_paths=['/usr'], fail_raise=True)()
try:
    os.unlink(sys.argv[5] + '/payload')
except PermissionError:
    pass
else:
    raise AssertionError('sibling must not be able to remove the outside fixture')
print('ready', flush=True)
assert sys.stdin.buffer.read(1) == b'G'
os.rename(sys.argv[3], sys.argv[4])
os.symlink(sys.argv[5], sys.argv[3], target_is_directory=True)
print('swapped', flush=True)
os._exit(0)
'''
    root = str(Path(__file__).resolve().parents[3])
    with subprocess.Popen(
        [sys.executable, '-I', '-S', '-c', script, root, str(shared),
         str(scope), str(parked), str(outside)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as child:
        try:
            assert _line(child.stdout) == b'ready\n'
            unlink = os.unlink
            raced = False

            def race(path, *args, **kwargs):
                nonlocal raced
                if os.path.basename(path) == 'payload' and not raced:
                    raced = True
                    child.stdin.write(b'G')
                    child.stdin.flush()
                    assert _line(child.stdout) == b'swapped\n'
                return unlink(path, *args, **kwargs)

            with monkeypatch.context() as patch:
                patch.setattr(os, 'unlink', race)
                _spawn._cleanup_stub(str(stub))
            assert raced, 'cleanup never reached the synchronized unlink boundary'
            assert child.wait(timeout=10) == 0, child.stderr.read()
            assert marker.read_text() == 'keep'
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
