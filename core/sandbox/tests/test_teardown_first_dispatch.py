"""The real Landlock-only dispatcher applies teardown-first without a timeout."""

import errno
import os
import select
import subprocess
import sys

import pytest

from core.sandbox import context as ctx
from core.sandbox.tests.capability import requires_landlock
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs


@requires_landlock
@pytest.mark.parametrize("timeout", [None, 10], ids=["no-timeout", "finite-timeout"])
@pytest.mark.parametrize("fault", ["interrupt", "io", "unconfirmed-ebadf"])
def test_real_fallback_retires_the_sweeper_before_propagating_failure(tmp_path, monkeypatch, timeout, fault):
    if sys.platform != "linux":
        pytest.skip("real Linux Landlock-only backend")
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    ready_r, ready_w = os.pipe()
    park_r, park_w = os.pipe()
    processes, streams = [], []
    primary = (KeyboardInterrupt("owned cancellation") if fault == "interrupt" else
               OSError(errno.EBADF if fault == "unconfirmed-ebadf" else errno.EIO,
                       "owned communication loss"))
    real_popen = subprocess.Popen
    def create(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        processes.append((proc, proc.kill, proc.wait))
        streams.extend(s for s in (proc.stdin, proc.stdout, proc.stderr) if s is not None)
        poller = select.poll()
        poller.register(ready_r, select.POLLIN)
        assert poller.poll(5000), "real confined target never became ready"
        assert os.read(ready_r, 1) == b"R"
        original = proc.communicate
        count = 0
        def communicate(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 1 or fault == "unconfirmed-ebadf":
                raise primary
            return original(*args, **kwargs)
        monkeypatch.setattr(proc, "communicate", communicate)
        if fault == "unconfirmed-ebadf":
            def wait(*args, **kwargs):
                raise OSError("owned wait result unavailable")
            monkeypatch.setattr(proc, "wait", wait)
        return proc
    patch_module_attribute(monkeypatch, ctx, "subprocess", "Popen", create)
    monkeypatch.setattr(ctx, "check_net_available", lambda: False)
    monkeypatch.setattr(ctx, "check_mount_available", lambda: False)
    script = ("import os,select\n"
              f"os.write({ready_w}, b'R')\n"
              "p=select.poll()\n"
              f"p.register({park_r}, select.POLLIN)\n"
              "p.poll(2000)\n")
    try:
        with ctx.sandbox(target=str(tmp_path), output=str(tmp_path),
                         block_network=False, restrict_reads=True) as run:
            with pytest.raises(type(primary)) as raised:
                run([os.path.realpath(sys.executable), "-P", "-c", script],
                    pass_fds=(ready_w, park_r), capture_output=True, timeout=timeout)
        assert raised.value is primary
        assert len(processes) == 1, "fallback bypassed the teardown-first executor"
        if fault == "unconfirmed-ebadf":
            assert primary.sandbox_process is processes[0][0]
            assert primary.sandbox_cleanup_pending
        else:
            assert processes[0][0].returncode not in (None, -9), "sweeper killed before retiring its target"
    finally:
        for proc, kill, wait in processes:
            if proc.returncode is None:
                kill()
            wait(timeout=5)
        for stream in streams:
            if not stream.closed:
                stream.close()
        for fd in (ready_r, ready_w, park_r, park_w):
            os.close(fd)
