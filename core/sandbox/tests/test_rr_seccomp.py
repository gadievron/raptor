"""Counter filtering must never enable CPU-wide or foreign-namespace monitoring."""
import ctypes
import json
import os
import sys

import pytest

from core.sandbox import seccomp

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux seccomp')


@pytest.mark.parametrize('profile', ['full', 'debug', 'frida', 'rr'])
@pytest.mark.parametrize('audit', [False, True])
def test_actual_perf_filter(profile, audit):
    if not seccomp.check_seccomp_available():
        pytest.skip('libseccomp unavailable')
    # Import/resolve everything before fork and before audit's open tracing.
    library = ctypes.CDLL(None, use_errno=True)
    from core.sandbox import state
    lib = state._libseccomp_cache
    number = lib.seccomp_syscall_resolve_name(b'perf_event_open')
    if number < 0:
        pytest.skip('perf syscall unavailable')
    ctypes.set_errno(0)
    library.syscall(number, ctypes.c_void_p(), ctypes.c_long(0),
                    ctypes.c_long(-1), ctypes.c_long(-1), ctypes.c_long(0))
    baseline_error = ctypes.get_errno()
    # Some CI hosts deny perf before copying attr. The real rr acceptance
    # test separately requires a working PMU; never assume host permission.
    assert baseline_error in (1, 13, 14)
    preexec = seccomp._make_seccomp_preexec(profile, audit_mode=audit)
    cases = [(0, 0xffffffff, 0), (0, 0xffffffffffffffff, 0),
             (0, 0, 0), (0, 1, 0), (0xffffffff, 0xffffffff, 0),
             (0xffffffffffffffff, 0xffffffff, 0), (0x100000000, 0xffffffff, 0),
             (0, 0x100000000, 0), (0, 0xffffffff, 4)]
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        preexec()
        values = []
        for target, cpu, flags in cases:
            ctypes.set_errno(0)
            # NULL attr: a permitted syscall fails EFAULT before allocating
            # a counter. EPERM demonstrates our hard deny, even in audit.
            library.syscall(number, ctypes.c_void_p(), ctypes.c_ulong(target),
                            ctypes.c_ulong(cpu), ctypes.c_long(-1), ctypes.c_ulong(flags))
            values.append(ctypes.get_errno())
        os.write(write_fd, json.dumps(values).encode())
        os._exit(0)
    os.close(write_fd)
    try:
        data = os.read(read_fd, 4096)
    finally:
        os.close(read_fd)
        _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    values = json.loads(data)
    assert values == ([baseline_error, baseline_error] + [1]*7 if profile == 'rr' else [1]*len(cases)), values


@pytest.mark.parametrize('consent', [None, 'landlock'])
def test_rr_refuses_missing_namespaces_even_with_general_floor_consent(tmp_path, monkeypatch, consent):
    from core.sandbox import context, state, SandboxSetupError
    monkeypatch.setattr(state, '_cli_sandbox_profile', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    monkeypatch.setattr(state, '_cli_sandbox_floor', consent)
    monkeypatch.setattr(context, 'check_seccomp_available', lambda: True)
    monkeypatch.setattr(context, 'check_mount_available', lambda: False)
    with pytest.raises(SandboxSetupError, match='lower sandbox floor'):
        context.run(['/usr/bin/true'], profile='rr', output=str(tmp_path),
                    require_fresh_procfs=False, restrict_reads=False, fake_home=False)


def test_rr_refuses_host_network_bridges(tmp_path, monkeypatch):
    from core.sandbox import context, state, SandboxSetupError
    monkeypatch.setattr(state, '_cli_sandbox_profile', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    with pytest.raises(SandboxSetupError, match='egress proxies'):
        context.run(['/usr/bin/true'], profile='rr', output=str(tmp_path),
                    use_egress_proxy=True, proxy_hosts=['example.com'])


def test_library_disabled_flag_cannot_erase_rr_contract(tmp_path, monkeypatch):
    from core.sandbox import context, state, SandboxSetupError
    monkeypatch.setattr(state, '_cli_sandbox_profile', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    with pytest.raises(SandboxSetupError, match='disabled=True'):
        context.run(['/usr/bin/true'], profile='rr', output=str(tmp_path), disabled=True)
