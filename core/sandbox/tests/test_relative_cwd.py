"""Non-image relative working directories retain the caller's base after pivot."""
import os
from pathlib import Path
import sys

import pytest

from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns
from core.testing.standalone_cli import run_standalone_cli
from core.testing.module_views import module_function_view


@pytest.mark.slow
@pytest.mark.linux_native
@requires_landlock
@requires_mount
@requires_userns
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux native mount transition')
@pytest.mark.parametrize('kind', ['text', 'bytes', 'path'])
def test_relative_cwd_uses_owned_parent_directory(tmp_path, kind):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    driver = r'''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
assert os.getcwd() == sys.argv[2]
from core.sandbox import sandbox
target = str(Path(sys.argv[2]) / 'target')
output = str(Path(sys.argv[2]) / 'output')
with sandbox(profile='strict', target=target, output=output) as run:
    positive = run(['/bin/sh', '-c', 'pwd'], cwd=target,
                   capture_output=True, text=True, timeout=15)
    assert positive.returncode == 0, positive.stderr
    assert positive.stdout.strip() == target
    assert positive.sandbox_info['mount_ns_active'] is True
    print('ABSOLUTE_NATIVE_OK', flush=True)
    relative = b'target' if sys.argv[3] == 'bytes' else Path('target') if sys.argv[3] == 'path' else 'target'
    actual = run(['/bin/sh', '-c', 'pwd'], cwd=relative,
                 capture_output=True, text=True, timeout=15)
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout.strip() == target
    assert actual.sandbox_info['mount_ns_active'] is True
    print('RELATIVE_NATIVE_OK', flush=True)
'''
    root = Path(__file__).resolve().parents[3]
    result = run_standalone_cli(
        [sys.executable, '-I', '-c', driver, str(root), str(tmp_path), kind],
        env=dict(os.environ), cwd=tmp_path, capture_output=True, text=True, timeout=40,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == ['ABSOLUTE_NATIVE_OK', 'RELATIVE_NATIVE_OK']


@pytest.mark.parametrize('cwd', ['image-relative', b'image-relative', Path('image-relative')],
                         ids=['text', 'bytes', 'path'])
def test_image_relative_cwd_does_not_read_host_cwd_before_launch(cwd):
    from core.sandbox import _spawn

    class BeforeLaunch(BaseException):
        pass

    calls = []

    def no_host_cwd():
        pytest.fail('image cwd must not resolve against host cwd')

    def stop_at_descriptor_validation(descriptor):
        calls.append(descriptor)
        raise BeforeLaunch()

    private = module_function_view(_spawn, bindings={
        'os': module_function_view(os, bindings={
            'getcwd': no_host_cwd, 'fstat': stop_at_descriptor_validation,
        }),
    })
    with pytest.raises(BeforeLaunch):
        private.run_sandboxed(
            ['/bin/true'], target=None, output=None, block_network=True,
            nproc_limit=64, limits={}, writable_paths=[], readable_paths=None,
            allowed_tcp_ports=None, seccomp_profile=None, seccomp_block_udp=False,
            env={}, cwd=cwd, timeout=1, pass_fds=(0,), rootfs='/owned-image',
        )
    assert calls == [0]
