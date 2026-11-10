"""Actual Landlock/seccomp/ptrace IO on a privately selected fallback route."""
from contextlib import contextmanager
import subprocess
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.capability import requires_landlock
from core.testing.module_views import module_function_view


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux audit backend')]
COMMAND = ['/bin/sh', '-c', 'printf audit-out; printf audit-err >&2']


@pytest.fixture
def audit_run(tmp_path):
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available

    if not (check_ptrace_available() and check_seccomp_available()):
        pytest.skip('requires actual ptrace and seccomp audit support')
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    # Select the supported namespace-unavailable route locally. Landlock,
    # seccomp, ptrace, audit-required and production floor checks remain real.
    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__,
        'check_net_available': lambda: False,
        'check_mount_available': lambda: False,
    })
    with contextmanager(private.sandbox)(
        profile='full', target=str(target), output=str(output),
        block_network=False, audit=True, audit_required=True,
    ) as run:
        yield run, output


@pytest.mark.parametrize('text', [False, True], ids=['bytes', 'text'])
def test_audit_explicit_stdout_pipe_merges_stderr(audit_run, text):
    run, _ = audit_run
    positive = run(COMMAND, capture_output=True, text=text, timeout=15)
    assert positive.returncode == 0
    assert positive.stdout == ('audit-out' if text else b'audit-out')
    assert positive.stderr == ('audit-err' if text else b'audit-err')
    assert positive.sandbox_info['audit_engaged'] is True
    actual = run(COMMAND, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                 text=text, timeout=15)
    assert actual.returncode == 0
    assert actual.stdout == ('audit-outaudit-err' if text else b'audit-outaudit-err')
    assert actual.stderr is None
    assert actual.sandbox_info['audit_engaged'] is True


@pytest.mark.parametrize('mode', ['stdout', 'stderr', 'both'])
@pytest.mark.parametrize('text', [False, True], ids=['bytes', 'text'])
def test_audit_explicit_pipes_keep_uncaptured_streams(audit_run, capfd, mode, text):
    run, _ = audit_run
    flags = {name: subprocess.PIPE for name in ('stdout', 'stderr')
             if mode in (name, 'both')}
    actual = run(COMMAND, text=text, timeout=15, **flags)
    inherited = capfd.readouterr()
    assert actual.returncode == 0 and actual.sandbox_info['audit_engaged'] is True
    for name, marker in (('stdout', 'audit-out'), ('stderr', 'audit-err')):
        if name in flags:
            assert getattr(actual, name) == (marker if text else marker.encode())
        else:
            assert getattr(actual, name) is None
            assert marker in (inherited.out if name == 'stdout' else inherited.err)


@pytest.mark.parametrize('redirect', ['stdout', 'stderr'])
def test_audit_file_redirect_remains_borrowed(audit_run, redirect):
    run, output = audit_run
    path = output / 'redirected'
    captured = 'stderr' if redirect == 'stdout' else 'stdout'
    with path.open('wb') as stream:
        actual = run(COMMAND, timeout=15, **{redirect: stream, captured: subprocess.PIPE})
        assert not stream.closed
    assert actual.returncode == 0 and actual.sandbox_info['audit_engaged'] is True
    assert getattr(actual, redirect) is None
    assert getattr(actual, captured) == (b'audit-err' if captured == 'stderr' else b'audit-out')
    assert path.read_bytes() == (b'audit-out' if redirect == 'stdout' else b'audit-err')


def test_audit_explicit_pipe_timeout_keeps_uncaptured_none(audit_run):
    run, _ = audit_run
    positive = run(['/bin/sh', '-c', 'printf ready'], capture_output=True, timeout=15)
    assert positive.stdout == b'ready' and positive.sandbox_info['audit_engaged'] is True
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        run(['/bin/sh', '-c', 'printf audit-timeout; exec /bin/sleep 30'],
            stdout=subprocess.PIPE, timeout=1)
    assert caught.value.output == b'audit-timeout'
    assert caught.value.stderr is None


def test_audit_explicit_stderr_pipe_keeps_selected_codec(audit_run):
    run, _ = audit_run
    actual = run(['/bin/sh', '-c', 'printf "caf\\351" >&2'],
                 stderr=subprocess.PIPE, encoding='latin-1', timeout=15)
    assert actual.returncode == 0 and actual.sandbox_info['audit_engaged'] is True
    assert actual.stdout is None and actual.stderr == 'café'
