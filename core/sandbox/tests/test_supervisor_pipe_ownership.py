"""A non-exec supervisor must not keep its target's RPC pipes alive."""

from pathlib import Path
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux fork backend")


def test_pid1_waiter_drops_rpc_ends_but_reports_target_status(tmp_path):
    # Exercise the actual waiter in a disposable process. It can mirror/reap
    # a child outside a PID namespace, so this ownership regression does not
    # need unprivileged namespaces or a relaxed sandbox policy.
    script = r'''
import os, select, signal, sys
sys.path.insert(0, sys.argv[1])
from core.sandbox._spawn import _pid1_split_for_waiter, _prepare_exec_fds

incoming_r, incoming_w = os.pipe()
outgoing_r, outgoing_w = os.pipe()
status_r, status_w = os.pipe()
ready_r, ready_w = os.pipe()
child = os.fork()
if child == 0:
    os.setpgid(0, 0)
    _pid1_split_for_waiter(status_w)
    # The target retains its two RPC ends and a setup-control descriptor.
    # The waiter must retain neither declared RPC ends nor ambient copies.
    _prepare_exec_fds((incoming_r, outgoing_w), ready_w)
    os.write(outgoing_w, b'ready')
    assert os.read(incoming_r, 1) == b''
    os.write(outgoing_w, b'eof')
    os._exit(0)

try:
    os.setpgid(child, child)
    os.close(incoming_r)
    os.close(outgoing_w)
    os.close(status_w)
    os.close(ready_w)
    def read(fd, size):
        assert select.select([fd], [], [], 3)[0], 'pipe EOF was pinned by supervisor'
        return os.read(fd, size)
    assert read(outgoing_r, 5) == b'ready'
    os.close(incoming_w)
    incoming_w = -1
    assert read(outgoing_r, 3) == b'eof'
    assert read(outgoing_r, 1) == b''
    assert read(status_r, 64) == b'0'
    assert read(status_r, 1) == b''
    _, status = os.waitpid(child, 0)
    child = 0
    assert os.waitstatus_to_exitcode(status) == 0
finally:
    if child:
        # Keep the waiter unreaped until its process group has been swept.
        os.killpg(child, signal.SIGKILL)
        os.waitpid(child, 0)
'''
    reply = subprocess.run(
        [sys.executable, "-I", "-c", script, str(Path(__file__).resolve().parents[3])],
        cwd=tmp_path, capture_output=True, text=True, timeout=10,
        start_new_session=True)
    assert reply.returncode == 0, reply.stderr
