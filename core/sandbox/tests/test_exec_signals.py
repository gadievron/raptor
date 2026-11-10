"""Native child exec follows subprocess signal restoration without changing its parent."""
from contextlib import contextmanager
import signal
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns
from core.testing.module_views import module_function_view


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux native signal delivery')]
COMMAND = ['/bin/sh', '-c', 'printf before; kill -s PIPE "$$"; printf after']


@pytest.fixture(params=[pytest.param('namespace', marks=[requires_mount, requires_userns]), 'audit'])
def execution(tmp_path, request):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    backend = request.param
    if backend == 'namespace':
        owner = context.sandbox(profile='strict', target=str(target), output=str(output))
    else:
        from core.sandbox.ptrace_probe import check_ptrace_available
        from core.sandbox.seccomp import check_seccomp_available
        if not (check_ptrace_available() and check_seccomp_available()):
            pytest.skip('requires actual ptrace and seccomp audit support')
        # Select the fallback only in this private routing view; policies run normally.
        private = module_function_view(context, bindings={
            'sandbox': context.sandbox.__wrapped__,
            'check_net_available': lambda: False,
            'check_mount_available': lambda: False,
        })
        owner = contextmanager(private.sandbox)(
            profile='full', target=str(target), output=str(output),
            block_network=False, audit=True, audit_required=True)
    with owner as run:
        yield run, backend


@pytest.mark.parametrize('setting', ['default', True, False], ids=['default', 'restore', 'preserve'])
def test_child_sigpipe_disposition_preserves_subprocess_contract(execution, setting):
    run, backend = execution
    before = signal.getsignal(signal.SIGPIPE)
    assert before == signal.SIG_IGN, 'the owning Python process starts with SIGPIPE ignored'
    # Empty SIG_BLOCK reads the current mask without changing any member.
    assert signal.SIGPIPE not in signal.pthread_sigmask(signal.SIG_BLOCK, [])
    positive = run(['/bin/sh', '-c', 'printf ready'], capture_output=True, timeout=15)
    assert positive.returncode == 0 and positive.stdout == b'ready'
    assert positive.sandbox_info['mount_ns_active' if backend == 'namespace' else 'audit_engaged'] is True
    options = {} if setting == 'default' else {'restore_signals': setting}
    try:
        actual = run(COMMAND, capture_output=True, timeout=15, **options)
    finally:
        assert signal.getsignal(signal.SIGPIPE) == before
    assert actual.returncode == (0 if setting is False else -signal.SIGPIPE), actual.stderr
    assert actual.stdout == (b'beforeafter' if setting is False else b'before')
    assert actual.stderr == b''


@pytest.mark.parametrize('restore', [True, False], ids=['restore', 'preserve'])
def test_trusted_reference_signal_contract(restore):
    # The approved trusted runtime uses the ordinary subprocess path. This
    # establishes the signal oracle, not a confinement claim for profile=none.
    before = signal.getsignal(signal.SIGPIPE)
    assert before == signal.SIG_IGN
    with context.sandbox(profile='none') as run:
        actual = run(COMMAND, capture_output=True, timeout=15, restore_signals=restore)
    # The trusted wrapper may mirror a signal through its supervisor as 128+sig.
    expected = (-signal.SIGPIPE, 128 + signal.SIGPIPE) if restore else (0,)
    assert actual.returncode in expected, actual.stderr
    assert actual.stdout == (b'before' if restore else b'beforeafter')
    assert actual.stderr == b'' and signal.getsignal(signal.SIGPIPE) == before
