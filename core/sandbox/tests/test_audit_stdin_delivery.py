"""Input delivery through the actual Linux Landlock audit backend."""

from contextlib import contextmanager
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.capability import requires_landlock
from core.testing.module_views import module_function_view


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux audit backend')
@requires_landlock
@pytest.mark.parametrize('payload', [b'owned audit stdin witness', b'', b'owned\x00binary'])
def test_audit_backend_delivers_supplied_input(tmp_path, payload):
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available

    if not (check_ptrace_available() and check_seccomp_available()):
        pytest.skip('requires actual ptrace and seccomp audit support')
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__,
        'check_net_available': lambda: False,
        'check_mount_available': lambda: False,
    })
    with contextmanager(private.sandbox)(
        profile='full', target=str(target), output=str(output),
        block_network=False, audit=True, audit_required=True,
    ) as run:
        result = run(['/bin/cat'], input=payload,
                     capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.sandbox_info['audit_engaged'] is True
    assert result.stdout == payload
