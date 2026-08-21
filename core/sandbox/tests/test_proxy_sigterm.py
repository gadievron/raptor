"""SIGTERM-safe teardown for the egress-proxy singleton.

``atexit`` only fires on normal interpreter exit: a SIGTERM'd RAPTOR
(CI timeout, systemd stop, operator kill) previously died without
closing the proxy's listeners or unlinking the unix-lane ``.sock``
files. ``get_proxy()`` now installs a chaining SIGTERM hook that runs
``stop(drain_timeout=0)`` and then re-delivers the signal.

SIGKILL remains uncatchable — that residual is documented on the hook.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from core.sandbox import proxy as proxy_mod

_RAPTOR_DIR = Path(__file__).resolve().parents[3]


@pytest.fixture
def sigterm_state():
    """Snapshot + restore the process SIGTERM disposition and the
    module's one-shot install flag."""
    prev = signal.getsignal(signal.SIGTERM)
    prev_flag = proxy_mod._sigterm_hook_installed
    proxy_mod._sigterm_hook_installed = False
    yield
    signal.signal(signal.SIGTERM, prev)
    proxy_mod._sigterm_hook_installed = prev_flag


class _StopRecorder:
    def __init__(self):
        self.calls = []

    def stop(self, *, drain_timeout=5.0):
        self.calls.append(drain_timeout)


class TestInstallSemantics:

    def test_hook_stops_instance_and_chains_prev_handler(
            self, sigterm_state, monkeypatch):
        chained = []
        signal.signal(signal.SIGTERM, lambda s, f: chained.append(s))
        proxy_mod._install_sigterm_cleanup()
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        recorder = _StopRecorder()
        monkeypatch.setattr(proxy_mod, "_instance", recorder)
        handler(signal.SIGTERM, None)
        assert recorder.calls == [0], (
            "hook must stop the singleton with drain_timeout=0")
        assert chained == [signal.SIGTERM], (
            "a pre-existing callable handler must be chained, not "
            "clobbered")

    def test_sig_ign_is_respected(self, sigterm_state):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        proxy_mod._install_sigterm_cleanup()
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_IGN
        assert proxy_mod._sigterm_hook_installed is False

    def test_installed_once(self, sigterm_state, monkeypatch):
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        proxy_mod._install_sigterm_cleanup()
        first = signal.getsignal(signal.SIGTERM)
        proxy_mod._install_sigterm_cleanup()
        assert signal.getsignal(signal.SIGTERM) is first

    def test_off_main_thread_is_skipped(self, sigterm_state):
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        done = threading.Event()
        t = threading.Thread(
            target=lambda: (proxy_mod._install_sigterm_cleanup(),
                            done.set()),
        )
        t.start()
        t.join(timeout=5.0)
        assert done.is_set()
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
        assert proxy_mod._sigterm_hook_installed is False


_CHILD_SCRIPT = r"""
import sys, time
from core.sandbox import proxy as proxy_mod
p = proxy_mod.get_proxy(["example.com"])
p.bind_unix(sys.argv[1])
print("READY", flush=True)
time.sleep(30)
"""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_sigterm_unlinks_lane_socket(short_sock_dir):
    """End-to-end: TERM a process holding a unix lane — the socket
    file must be unlinked and the process must still die by TERM."""
    # short_sock_dir, not tmp_path: AF_UNIX paths must fit sun_path
    # (~104 bytes on macOS), which pytest's tmp_path exceeds on CI
    # runners (see the conftest fixture).
    sock = short_sock_dir / "lane.sock"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_RAPTOR_DIR)
    proc = subprocess.Popen(
        [sys.executable, "-c", _CHILD_SCRIPT, str(sock)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, text=True,
    )
    try:
        line = proc.stdout.readline()
        assert line.strip() == "READY", (
            f"child failed to start: {proc.stderr.read()}"
        )
        assert sock.exists()
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=15)
        assert rc == -signal.SIGTERM, (
            "process must still terminate with the default TERM "
            f"disposition after cleanup (got rc={rc})")
        assert not sock.exists(), (
            "SIGTERM teardown must unlink the unix-lane socket")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
