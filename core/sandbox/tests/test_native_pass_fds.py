"""Native exec preserves audited descriptors without leaking ambient capabilities."""
import os
import subprocess
import sys

import pytest

from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux fork backend")


def test_exec_descriptor_sweep_preserves_only_declared_capabilities(tmp_path):
    driver = r'''
import os, sys
from core.sandbox._spawn import _prepare_exec_fds
allowed = os.open(sys.argv[1], os.O_RDONLY)
ambient = os.open(sys.argv[1], os.O_RDONLY)
os.set_inheritable(ambient, True)
status_r, status_w = os.pipe()
child = os.fork()
if child:
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert not os.get_inheritable(allowed)
    assert os.get_inheritable(ambient)
    assert not os.get_inheritable(status_w)
    sys.exit(0)
_prepare_exec_fds((allowed,), status_w)
os.execv(sys.executable, [sys.executable, '-I', '-c', ''' + repr('''
import os, sys
assert os.read(int(sys.argv[1]), 8) == b"receipt"
for value in sys.argv[2:]:
    try: os.fstat(int(value))
    except OSError: pass
    else: raise AssertionError("undeclared descriptor survived exec")
''') + ''', str(allowed), str(ambient), str(status_r), str(status_w)])
'''
    receipt = tmp_path / "receipt"
    receipt.write_bytes(b"receipt")
    result = subprocess.run([sys.executable, "-c", driver, str(receipt)],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr


@requires_landlock
@requires_mount
@requires_userns
def test_native_pass_fds_and_input_keep_strict_namespace_policy(tmp_path):
    from core.sandbox import sandbox
    receipt = tmp_path / "receipt"
    receipt.write_bytes(b"receipt")
    descriptor = os.open(receipt, os.O_RDONLY)
    try:
        # This probes descriptor/namespace plumbing, not the pytest runner's
        # home-directory venv. Use the system runtime already in the bind tree
        # and disable user environment/site startup; never grant all of HOME.
        executable = os.path.realpath("/usr/bin/python3")
        if not os.path.isfile(executable):
            pytest.skip("system Python 3 required for the namespace probe")
        with sandbox(profile="strict", target=str(tmp_path), output=str(tmp_path)) as run:
            result = run([executable, "-I", "-S", "-c",
                          "import os,sys; assert os.read(int(sys.argv[1]),8)==b'receipt'; "
                          "assert sys.stdin.read()=='witness'; print('ok')", str(descriptor)],
                         pass_fds=(descriptor,), input="witness", capture_output=True,
                         text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ok"
        assert result.sandbox_info["mount_ns_active"]
    finally:
        os.close(descriptor)


def test_audited_descriptors_reach_native_dispatch_with_input(tmp_path, monkeypatch):
    from core.sandbox import context, _spawn, probes
    receipt = tmp_path / "receipt"
    receipt.write_bytes(b"receipt")
    descriptor = os.open(receipt, os.O_RDONLY)
    calls = []
    def native(command, **kwargs):
        calls.append(kwargs)
        assert kwargs["pass_fds"] == (descriptor,)
        assert os.read(descriptor, 8) == b"receipt"
        assert kwargs["stdin"].read() == b"witness"
        result = subprocess.CompletedProcess(command, 0, "ok", "")
        result._setup_status = None
        return result
    monkeypatch.setattr(context, "check_net_available", lambda: True)
    monkeypatch.setattr(context, "check_mount_available", lambda: True)
    monkeypatch.setattr(probes, "check_unshare_engages", lambda flags: (True, ""))
    monkeypatch.setattr(_spawn, "mount_ns_available", lambda: True)
    monkeypatch.setattr(_spawn, "run_sandboxed", native)
    try:
        with context.sandbox(target=str(tmp_path), output=str(tmp_path)) as run:
            result = run(["/usr/bin/true"], pass_fds=(descriptor,), input="witness",
                         text=True, capture_output=True, timeout=5)
        assert result.returncode == 0
        assert len(calls) == 1
    finally:
        os.close(descriptor)


def test_status_pipe_collision_refuses_before_changing_any_descriptors():
    from core.sandbox._spawn import _prepare_exec_fds
    read_fd, status_fd = os.pipe()
    try:
        original = tuple(os.get_inheritable(fd) for fd in (read_fd, status_fd))
        with pytest.raises(ValueError, match="overlap.*status pipe"):
            _prepare_exec_fds((read_fd, status_fd), status_fd)
        for fd in (read_fd, status_fd):
            os.fstat(fd)
        assert tuple(os.get_inheritable(fd) for fd in (read_fd, status_fd)) == original
    finally:
        os.close(read_fd)
        os.close(status_fd)
