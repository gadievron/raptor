"""Per-request process-group cleanup in the sandbox host daemon.

The spawn/probe/conversation handlers start request targets as the
leader of a new session (``start_new_session=True``) and SIGKILL the
request's whole process group on every exit path. Pre-fix the handlers
used a plain Popen/subprocess.run and killed only the direct pid, so a
double-fork descendant survived the request and leaked into later RPCs
inside the persistent sandbox (demonstrated live: the grandchild was
still running after ``_handle_spawn`` returned).

Pipe-level tests — handlers are called in-process, no sandbox needed.
"""

from __future__ import annotations

import json
import os
import sys
import time

import pytest

from core.sandbox import _daemon

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="handlers spawn real subprocesses and use killpg semantics "
           "pinned on Linux",
)

# Target that double-forks a detached lingerer, reports its pid on
# stdout, then runs an optional payload (echo loop / sleep) in the
# direct child. The grandchild drops the inherited stdio pipes so the
# handler's capture is never held open by it.
_FORKER = r"""
import json, os, sys, time
pidfile = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "exit"
pid = os.fork()
if pid == 0:
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    with open(pidfile, "w") as f:
        f.write(str(os.getpid()))
    time.sleep(120)
    os._exit(0)
# Direct child: wait until the grandchild has written its pidfile so
# the test never races the fork.
for _ in range(200):
    if os.path.exists(pidfile):
        break
    time.sleep(0.01)
if mode == "echo":
    line = sys.stdin.readline()
    sys.stdout.write(line)
    sys.stdout.flush()
elif mode == "hang":
    print(json.dumps({"grandchild": pid}), flush=True)
    time.sleep(120)
print(json.dumps({"grandchild": pid}))
"""


def _read_grandchild_pid(pidfile: str) -> int:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            with open(pidfile) as f:
                text = f.read().strip()
            if text:
                return int(text)
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError("grandchild never wrote its pidfile")


def _assert_dead(pid: int, what: str) -> None:
    """The pid must be gone (or a reaped-any-moment zombie) shortly
    after the handler returns — killpg is synchronous, only init's
    reap of the orphan is asynchronous."""
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/stat") as f:
                state = f.read().rsplit(")", 1)[1].split()[0]
        except OSError:
            return  # ESRCH — fully gone
        if state == "Z":
            return  # SIGKILLed, awaiting init's reap
        time.sleep(0.05)
    os.kill(pid, 9)  # don't leak the lingerer out of the test
    raise AssertionError(f"{what}: detached descendant {pid} survived "
                         f"the request (state={state})")


class TestSpawnSweepsDescendants:

    def test_success_path(self, tmp_path):
        pidfile = str(tmp_path / "gpid")
        resp = _daemon._handle_spawn({
            "argv": [sys.executable, "-c", _FORKER, pidfile],
            "timeout": 20.0,
        })
        assert resp["ok"] is True, resp
        out = json.loads(bytes.fromhex(resp["stdout_hex"]).decode())
        assert resp["timed_out"] is False
        _assert_dead(out["grandchild"], "spawn success path")

    def test_timeout_path(self, tmp_path):
        pidfile = str(tmp_path / "gpid")
        resp = _daemon._handle_spawn({
            "argv": [sys.executable, "-c", _FORKER, pidfile, "hang"],
            "timeout": 1.0,
        })
        assert resp["ok"] is True, resp
        assert resp["timed_out"] is True
        gpid = _read_grandchild_pid(pidfile)
        _assert_dead(gpid, "spawn timeout path")


class TestProbeSweepsDescendants:

    def test_success_path(self, tmp_path):
        pidfile = str(tmp_path / "gpid")
        resp = _daemon._handle_probe({
            "target_argv": [sys.executable, "-c", _FORKER, pidfile, "echo"],
            "steps": [{"send_template": "marco\\n",
                       "recv_until": "newline"}],
            "per_recv_timeout": 5.0,
            "total_wait_seconds": 5.0,
        })
        assert resp["ok"] is True, resp
        assert resp["target_exit"] == "clean", resp
        gpid = _read_grandchild_pid(pidfile)
        _assert_dead(gpid, "probe success path")

    def test_timeout_path(self, tmp_path):
        pidfile = str(tmp_path / "gpid")
        resp = _daemon._handle_probe({
            "target_argv": [sys.executable, "-c", _FORKER, pidfile, "hang"],
            "steps": [{"recv_until": "newline"}],
            "per_recv_timeout": 2.0,
            "total_wait_seconds": 1.0,
        })
        assert resp["ok"] is True, resp
        assert resp["target_exit"] == "timeout", resp
        gpid = _read_grandchild_pid(pidfile)
        _assert_dead(gpid, "probe timeout path")


class TestConversationSweepsDescendants:

    def test_success_path(self, tmp_path):
        pidfile = str(tmp_path / "gpid")
        resp = _daemon._handle_conversation({
            "target_argv": [sys.executable, "-c", _FORKER, pidfile, "echo"],
            "sends": [{"bytes_hex": b"polo\n".hex(),
                       "then_recv_until": "newline"}],
            "per_recv_timeout": 5.0,
            "total_wait_seconds": 5.0,
        })
        assert resp["ok"] is True, resp
        assert resp["target_exit"] == "clean", resp
        gpid = _read_grandchild_pid(pidfile)
        _assert_dead(gpid, "conversation success path")

    def test_timeout_path(self, tmp_path):
        pidfile = str(tmp_path / "gpid")
        resp = _daemon._handle_conversation({
            "target_argv": [sys.executable, "-c", _FORKER, pidfile, "hang"],
            "sends": [{"bytes_hex": b"x".hex(),
                       "then_recv_until": "newline"}],
            "per_recv_timeout": 2.0,
            "total_wait_seconds": 1.0,
        })
        assert resp["ok"] is True, resp
        assert resp["target_exit"] == "timeout", resp
        gpid = _read_grandchild_pid(pidfile)
        _assert_dead(gpid, "conversation timeout path")
