"""Timeout snapshots preserve raw bytes; successful text results remain text."""
from contextlib import contextmanager
import subprocess
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns
from core.testing.module_views import module_function_view


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux native timeout snapshots')]
RAW_OUT = b'\xff\r\n'
RAW_ERR = b'\xfe\r\n'
COMMAND = ['/bin/sh', '-c', 'printf "\\377\\r\\n"; printf "\\376\\r\\n" >&2; exec /bin/sleep 30']


@pytest.fixture(params=[pytest.param('namespace', marks=[requires_mount, requires_userns]), 'audit'])
def execution(tmp_path, request):
    backend = request.param
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    if backend == 'namespace':
        owner = context.sandbox(profile='strict', target=str(target), output=str(output))
    else:
        from core.sandbox.ptrace_probe import check_ptrace_available
        from core.sandbox.seccomp import check_seccomp_available
        if not (check_ptrace_available() and check_seccomp_available()):
            pytest.skip('requires actual ptrace and seccomp audit support')
        # Route isolation only; actual backend policy, audit gate and kernel calls run.
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


def assert_snapshot(execution, mode, text_options):
    run, backend = execution
    positive = run(['/bin/sh', '-c', 'printf ready'], capture_output=True,
                   timeout=15, **text_options)
    assert positive.returncode == 0
    assert positive.stdout == (b'ready' if text_options.get('text') is False else 'ready')
    assert positive.sandbox_info['mount_ns_active' if backend == 'namespace' else 'audit_engaged'] is True
    flags = {'capture_output': True} if mode == 'both' else {
        'stdout': subprocess.PIPE if mode == 'stdout' else subprocess.DEVNULL,
        'stderr': subprocess.PIPE if mode == 'stderr' else subprocess.DEVNULL,
    }
    command = COMMAND if mode != 'none' else ['/bin/sleep', '30']
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        run(command, timeout=1, **text_options, **flags)
    assert caught.value.output == (RAW_OUT if mode in ('both', 'stdout') else None)
    assert caught.value.stdout == caught.value.output
    assert caught.value.stderr == (RAW_ERR if mode in ('both', 'stderr') else None)


def test_text_timeout_preserves_raw_captured_bytes(execution):
    assert_snapshot(execution, 'both', {'text': True})


@pytest.mark.parametrize('mode,text_options', [
    ('both', {'text': False}),
    ('both', {'text': True, 'encoding': 'ascii', 'errors': 'strict'}),
    ('stdout', {'text': True}),
    ('stderr', {'text': True}),
    ('none', {'text': True}),
], ids=['bytes-control', 'strict-codec', 'stdout-only', 'stderr-only', 'uncaptured'])
def test_timeout_snapshot_stream_and_codec_contract(execution, mode, text_options):
    assert_snapshot(execution, mode, text_options)
