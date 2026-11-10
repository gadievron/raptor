"""Conflicting capture ownership must be refused before target execution."""

from contextlib import contextmanager
import subprocess
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns
from core.testing.module_views import module_function_view


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux native backends')]


@pytest.mark.parametrize('lane', [
    pytest.param('namespace', marks=[requires_mount, requires_userns]), 'audit',
])
@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
def test_conflicting_capture_refuses_before_execution(tmp_path, lane, stream):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    marker = output / 'must-not-run'
    bindings = {'sandbox': context.sandbox.__wrapped__}
    if lane == 'audit':
        from core.sandbox.ptrace_probe import check_ptrace_available
        from core.sandbox.seccomp import check_seccomp_available
        if not (check_ptrace_available() and check_seccomp_available()):
            pytest.skip('requires actual ptrace and seccomp audit support')
        bindings.update(check_net_available=lambda: False,
                        check_mount_available=lambda: False)
    private = module_function_view(context, bindings=bindings)
    command = ['/bin/sh', '-c', 'printf x >> "$1"', 'owned', str(marker)]
    with (output / 'redirect').open('wb') as borrowed:
        # This documents the existing subprocess contract without launching
        # its command: argument preparation rejects stream ownership first.
        with pytest.raises(ValueError, match='stdout and stderr'):
            subprocess.run(command, capture_output=True, **{stream: borrowed})
        assert not marker.exists()
        with contextmanager(private.sandbox)(
            profile='strict' if lane == 'namespace' else 'full',
            target=str(target), output=str(output), block_network=False,
            audit=lane == 'audit', audit_required=lane == 'audit',
        ) as run:
            positive = run(['/bin/sh', '-c',
                            'printf admitted' if stream == 'stdout' else 'printf admitted >&2'],
                           **{stream: borrowed}, timeout=15)
            assert positive.returncode == 0
            if lane == 'namespace':
                assert positive.sandbox_info['mount_ns_active'] is True
            else:
                assert positive.sandbox_info['audit_engaged'] is True
            caught = None
            try:
                run(command, capture_output=True, **{stream: borrowed}, timeout=15)
            except ValueError as error:
                caught = error
        assert not marker.exists(), 'conflicting capture arguments executed the target'
        assert isinstance(caught, ValueError)
        assert not borrowed.closed, 'borrowed redirect ownership changed'
    assert (output / 'redirect').read_bytes() == b'admitted'
