"""Tracer-ready descriptors are owned before their inheritable flag changes."""

import builtins
import errno
import os
import sys
import tempfile
from types import ModuleType

import pytest

from core.sandbox import _spawn as spawn, ptrace_probe, seccomp
from core.testing.module_views import module_function_view


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux native setup')


@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt, SystemExit, None],
                         ids=['flag-io', 'flag-interrupt', 'flag-exit', 'flags-ready'])
def test_tracer_ready_handoff_retires_unlaunched_native_pipes(tmp_path, failure_type):
    primary = (failure_type or KeyboardInterrupt)('owned prelaunch interruption')
    identities, pairs, roots, ready, forks = {}, [], [], [], []
    private_os = ModuleType('owned_prelaunch_os')
    vars(private_os).update(vars(os))

    def pipe():
        pair = os.pipe()
        pairs.append(pair)
        for fd in pair:
            info = os.fstat(fd)
            identities[fd] = (info.st_dev, info.st_ino)
        return pair

    def set_inheritable(fd, value):
        pair = next(pair for pair in pairs if pair[1] == fd)
        assert value is True
        os.set_inheritable(fd, value)
        assert os.get_inheritable(fd)
        ready.append(pair)
        if failure_type is not None:
            raise primary

    def stop_before_fork():
        forks.append(True)
        assert failure_type is None, 'flag failure must precede child launch'
        raise primary

    private_os.pipe = pipe
    private_os.set_inheritable = set_inheritable
    private_os.fork = stop_before_fork
    private_ptrace = module_function_view(ptrace_probe, bindings={'check_ptrace_available': lambda: True})
    private_seccomp = module_function_view(seccomp, bindings={'check_seccomp_available': lambda: True})
    private_tempfile = ModuleType('owned_prelaunch_tempfile')
    vars(private_tempfile).update(vars(tempfile))

    def own_root(*, prefix):
        root = tempfile.mkdtemp(prefix=prefix, dir=tmp_path)
        roots.append(root)
        return root

    private_tempfile.mkdtemp = own_root

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == 'ptrace_probe':
            return private_ptrace
        if level == 1 and name == 'seccomp':
            return private_seccomp
        if level == 0 and name == 'tempfile':
            return private_tempfile
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(spawn, import_hook=imports, bindings={
        'os': private_os, '_sweep_stale_audit_configs': lambda: None,
        '_make_seccomp_preexec': lambda *args, **kwargs: None,
        '_LIVE_DEATH_W': set(),
    })
    run_dir = tmp_path / 'run'
    run_dir.mkdir()
    try:
        with pytest.raises(type(primary)) as caught:
            private.run_sandboxed(
                ['/bin/true'], target=None, output=None, block_network=False,
                nproc_limit=0, limits={}, writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None, seccomp_profile='full', seccomp_block_udp=False,
                env={}, cwd=None, timeout=1, capture_output=False,
                audit_mode=True, audit_required=True, audit_run_dir=str(run_dir))
        assert caught.value is primary
        assert len(ready) == 1
        assert len(forks) == (failure_type is None)
        assert roots and all(not os.path.exists(root) for root in roots)
        for fd in identities:
            with pytest.raises(OSError) as closed:
                os.fstat(fd)
            assert closed.value.errno == errno.EBADF
    finally:
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)
        for root in roots:
            if os.path.exists(root):
                os.rmdir(root)
