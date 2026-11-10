"""Audited caller-approved read-only descriptors survive the audit lane."""

from contextlib import contextmanager
import os
import sys
import errno
from types import SimpleNamespace

import pytest

from core.sandbox import context, _landlock_audit as audit, evidence
from core.sandbox.tests.capability import requires_landlock
from core.testing.module_views import module_function_view


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux audit backend')]


@pytest.mark.parametrize('also_stdin', [False, True], ids=['extra-fd', 'stdin-and-extra'])
def test_admitted_readonly_descriptor_reaches_audited_target(tmp_path, also_stdin):
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available

    if not (check_ptrace_available() and check_seccomp_available()):
        pytest.skip('requires actual ptrace and seccomp audit support')
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    witness = b'owned descriptor witness'
    source = target / 'approved-input'
    source.write_bytes(witness)
    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__,
        'check_net_available': lambda: False,
        'check_mount_available': lambda: False,
    })
    with source.open('rb') as borrowed:
        descriptor = borrowed.fileno()
        assert not os.get_inheritable(descriptor)
        with contextmanager(private.sandbox)(
            profile='full', target=str(target), output=str(output),
            block_network=False, audit=True, audit_required=True,
        ) as run:
            result = run([
                sys.executable, '-I', '-S', '-B', '-c',
                'import os,sys; fd=int(sys.argv[1]); '
                'prefix=os.read(0,3) if sys.argv[2]=="yes" else b""; '
                'os.write(1,prefix+os.read(fd,64))',
                str(descriptor), 'yes' if also_stdin else 'no',
            ], pass_fds=(descriptor,), stdin=borrowed if also_stdin else None,
                capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
        assert result.sandbox_info['audit_engaged'] is True
        assert result.stdout == witness
        assert not borrowed.closed
        assert not os.get_inheritable(descriptor), 'child inheritance changed parent flags'


def test_closed_caller_number_is_rejected_before_internal_allocation(tmp_path):
    prepared = []

    def open_evidence(*args, **kwargs):
        prepared.append(True)
        raise AssertionError('invalid caller descriptor reached internal allocation')

    private_evidence = module_function_view(evidence, bindings={
        'EvidenceFile': SimpleNamespace(open=open_evidence),
    })
    private = module_function_view(audit, bindings={'_evidence_mod': private_evidence})
    descriptor = os.open(tmp_path / 'closed-owned-file', os.O_CREAT | os.O_RDONLY, 0o600)
    os.close(descriptor)
    with pytest.raises(OSError) as caught:
        private.run_landlock_audit(['unused'], audit_run_dir=str(tmp_path),
                                   pass_fds=(descriptor,))
    assert caught.value.errno == errno.EBADF
    assert prepared == []
