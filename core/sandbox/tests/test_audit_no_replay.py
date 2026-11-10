"""A completed audited command must not be replayed after parent cleanup fails."""

import builtins
from contextlib import contextmanager
import sys

import pytest

import core.sandbox as package
from core.sandbox import context, _landlock_audit as audit, evidence
from core.sandbox.tests.capability import requires_landlock
from core.sandbox.errors import SandboxSetupError
from core.testing.module_views import module_function_view


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux audit backend')]


@pytest.mark.parametrize('required,error_type,stage', [
    pytest.param(required, error_type, 'after', id=f'{name}-{required}-after')
    for required in (False, True)
    for name, error_type in [('io', OSError), ('runtime', RuntimeError), ('import', ImportError)]
] + [pytest.param(required, OSError, 'before', id=f'io-{required}-before')
     for required in (False, True)])
def test_execution_boundary_controls_fallback(tmp_path, required, error_type, stage):
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available

    if not (check_ptrace_available() and check_seccomp_available()):
        pytest.skip('requires actual ptrace and seccomp audit support')
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    marker = output / 'owned-marker'
    failure = error_type('owned evidence retirement failure')
    reached = []

    def finish(handle):
        result = evidence.finalize_capture(handle)
        reached.append(result)
        raise failure

    def prepare(*args, **kwargs):
        reached.append('before')
        raise failure

    private_evidence = module_function_view(evidence, bindings={'finalize_capture': finish})
    bindings = {'_evidence_mod': private_evidence}
    if stage == 'before':
        bindings['_write_audit_config'] = prepare
    backend = module_function_view(audit, bindings=bindings)
    parent = module_function_view(package, bindings={'_landlock_audit': backend})

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and not name and '_landlock_audit' in fromlist:
            return parent
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__,
        'check_net_available': lambda: False,
        'check_mount_available': lambda: False,
    }, import_hook=imports)
    caught = None
    with contextmanager(private.sandbox)(
        profile='full', target=str(target), output=str(output),
        block_network=False, audit=True, audit_required=required,
    ) as run:
        try:
            run(['/bin/sh', '-c', 'printf x >> "$1"', 'owned', str(marker)],
                capture_output=True, timeout=15)
        except BaseException as error:
            caught = error
    if stage == 'after':
        assert reached == [True], 'fault must follow actual evidence finalisation'
        assert marker.read_bytes() == b'x', 'audit failure replayed a completed command'
        assert caught is failure, 'late parent failure must retain its identity'
    else:
        assert reached == ['before'], 'setup fault must precede any target release'
        if required:
            assert isinstance(caught, SandboxSetupError)
            assert not marker.exists(), 'required audit must refuse non-audit execution'
        else:
            assert caught is None
            assert marker.read_bytes() == b'x', 'pre-execution fallback must remain available'
