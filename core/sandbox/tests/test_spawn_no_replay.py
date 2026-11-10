"""Namespace execution must not replay after parent retirement errors."""

import builtins
from contextlib import contextmanager
import sys
import subprocess

import pytest

import core.sandbox as package
from core.sandbox import context, _spawn as spawn, evidence
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns
from core.testing.module_views import module_function_view


pytestmark = [pytest.mark.slow, pytest.mark.linux_native, requires_landlock,
              requires_mount, requires_userns,
              pytest.mark.skipif(sys.platform != 'linux', reason='Linux namespace backend')]


def _private_context(backend):
    parent = module_function_view(package, bindings={'_spawn': backend})

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and not name and '_spawn' in fromlist:
            return parent
        return builtins.__import__(name, globals, locals, fromlist, level)

    return module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__,
    }, import_hook=imports)


@pytest.mark.parametrize('profile', ['full', 'strict'])
@pytest.mark.parametrize('error_type', [OSError, RuntimeError], ids=['io', 'runtime'])
def test_completed_namespace_command_is_not_replayed(tmp_path, profile, error_type):
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available

    if not (check_ptrace_available() and check_seccomp_available()):
        pytest.skip('requires actual ptrace and seccomp audit support')
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    marker = output / 'owned-marker'
    failure = error_type('owned post-execution evidence retirement failure')
    reached = []

    def finish(handle):
        result = evidence.finalize_capture(handle)
        reached.append(result)
        raise failure

    private_evidence = module_function_view(evidence, bindings={'finalize_capture': finish})
    evidence_parent = module_function_view(package, bindings={'evidence': private_evidence})

    def backend_imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and not name and 'evidence' in fromlist:
            return evidence_parent
        return builtins.__import__(name, globals, locals, fromlist, level)

    backend = module_function_view(spawn, import_hook=backend_imports)
    private = _private_context(backend)
    caught = None
    with contextmanager(private.sandbox)(
        profile=profile, target=str(target), output=str(output),
        block_network=False, audit=True,
    ) as run:
        try:
            run(['/bin/sh', '-c', 'printf x >> "$1"', 'owned', str(marker)],
                capture_output=True, timeout=15)
        except BaseException as error:
            caught = error
    assert reached == [True], f'namespace evidence seam not reached: {caught!r}'
    assert marker.read_bytes() == b'x', 'late namespace error replayed the command'
    assert caught is failure


@pytest.mark.parametrize('category', ['M', 'X'])
def test_reported_preexec_failure_keeps_namespace_retry(tmp_path, category):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    marker = output / 'owned-marker'
    calls = []

    def execute(cmd, **kwargs):
        calls.append(kwargs['skip_mount_ns'])
        if len(calls) == 1:
            # A typed setup result is the protocol under test; no first
            # target is launched. The retry uses the real native backend.
            kwargs['execution_committed_callback']()
            result = subprocess.CompletedProcess(cmd, 127, b'', b'')
            result._setup_status = (category, 'owned pre-exec failure')
            return result
        return spawn.run_sandboxed(cmd, **kwargs)

    backend = module_function_view(spawn, bindings={'run_sandboxed': execute})
    private = _private_context(backend)
    with contextmanager(private.sandbox)(profile='full', target=str(target),
                                        output=str(output), block_network=False) as run:
        result = run(['/bin/sh', '-c', 'printf x >> "$1"', 'owned', str(marker)],
                     capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert calls == [False, True]
    assert marker.read_bytes() == b'x'


def test_pre_release_exception_keeps_environmental_fallback(tmp_path):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    marker = output / 'owned-marker'
    reached = []

    def execute(cmd, **kwargs):
        reached.append(cmd)
        assert callable(kwargs['execution_committed_callback'])
        raise OSError('owned pre-release setup failure')

    backend = module_function_view(spawn, bindings={'run_sandboxed': execute})
    private = _private_context(backend)
    with contextmanager(private.sandbox)(profile='full', target=str(target),
                                        output=str(output), block_network=False) as run:
        result = run(['/bin/sh', '-c', 'printf x >> "$1"', 'owned', str(marker)],
                     capture_output=True, timeout=15)
    assert len(reached) == 1
    assert result.returncode == 0, result.stderr
    assert marker.read_bytes() == b'x'
