"""Worker cases run by test_server's child pytest session.

The persistent handler is intentionally process-owned. This file is not
collected by default; the parent driver owns the process and its teardown.
"""

import sys
import time

import pytest

from packages.ghidra.tests.test_server import short_sock_dir as short_sock_dir


class TestWorkerWatchdog:
    """Per-op hard deadline on the persistent handler — no JVM."""

    def test_hung_op_raises(self, monkeypatch):
        import threading

        from packages.ghidra import server_worker

        # Event-parked, not sleep-parked: a plain sleep(30) left the
        # daemon handler thread wedged for 30s AFTER the test passed,
        # bleeding scheduler pressure into the rest of the worker's
        # test batch. The release below unparks it immediately.
        release = threading.Event()

        def _stuck(session, req):
            release.wait(timeout=120)

        monkeypatch.setattr(server_worker, "_handle", _stuck)
        monkeypatch.setattr(
            server_worker, "_OP_DEADLINE_S", {"ping": 0.2},
        )
        handler = server_worker._HandlerThread(server_worker._Session())
        try:
            with pytest.raises(server_worker._OpHung, match="ping"):
                handler.run({"op": "ping"})
        finally:
            release.set()

    def test_fast_op_passes_through(self):
        from packages.ghidra import server_worker
        handler = server_worker._HandlerThread(server_worker._Session())
        out = handler.run({"op": "ping"})
        assert out == {"pong": True}

    def test_handler_error_propagates(self):
        from packages.ghidra import server_worker
        handler = server_worker._HandlerThread(server_worker._Session())
        with pytest.raises(RuntimeError, match="unknown op"):
            handler.run({"op": "frobnicate"})

    def test_single_thread_serves_every_op(self, monkeypatch):
        """One persistent handler thread (single JVM attachment),
        not a thread per op."""
        import threading as _threading

        from packages.ghidra import server_worker
        handler = server_worker._HandlerThread(server_worker._Session())
        seen = set()
        orig = server_worker._handle

        def _record(session, req):
            seen.add(_threading.get_ident())
            return orig(session, req)

        monkeypatch.setattr(server_worker, "_handle", _record)
        handler.run({"op": "ping"})
        handler.run({"op": "ping"})
        handler.run({"op": "ping"})
        assert len(seen) == 1, (
            f"expected 1 handler thread, saw {len(seen)}: {seen} "
            f"(main={_threading.get_ident()})"
        )
        assert _threading.get_ident() not in seen

    def test_decompile_deadline_tracks_request_timeout(self, monkeypatch):
        from types import SimpleNamespace

        from packages.ghidra import server_worker
        seen = {}
        # Exercise deadline calculation without starting a persistent JVM worker.
        handler = object.__new__(server_worker._HandlerThread)
        handler._closing = False
        handler._requests = SimpleNamespace(put=lambda request: None)

        class _Probe:
            def set(self):
                pass

            def wait(self, timeout=None):
                seen["deadline"] = timeout
                return True  # pretend completion; box empty → KeyError

        monkeypatch.setattr(
            server_worker, "threading", SimpleNamespace(Event=_Probe),
        )
        with pytest.raises(KeyError, match="result"):
            handler.run(
                {"op": "decompile", "function": "f", "timeout": 120},
            )
        assert seen["deadline"] == 135


class TestWorkerConnectionIdleTimeout:
    """The worker must exit when idle past --idle-timeout WITH a
    client connected, not only while waiting in accept() — an
    idle-but-connected (or wedged) parent must not hold the JVM
    worker process alive forever."""

    def _run_worker(self, sock_dir, monkeypatch, idle_timeout=1):
        import threading

        from packages.ghidra import server_worker

        sock_path = str(sock_dir / "w.sock")
        monkeypatch.setattr(
            sys, "argv",
            ["server_worker", sock_path,
             "--idle-timeout", str(idle_timeout)],
        )
        box: dict = {}

        def run():
            box["rc"] = server_worker.main()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return sock_path, thread, box

    @staticmethod
    def _connect_client(sock_path, thread=None, timeout=None):
        """Connect once the worker is actually LISTENING.

        The socket path exists after bind() but before listen(), so a
        connect raced against worker startup can hit
        ConnectionRefusedError under load. Mirror the production boot
        wait (GhidraServer.start): poll connect with a small sleep
        until a generous deadline, failing fast when the worker
        thread has already died.
        """
        import socket as socket_mod

        deadline = time.monotonic() + 10
        while True:
            client = socket_mod.socket(socket_mod.AF_UNIX,
                                       socket_mod.SOCK_STREAM)
            if timeout is not None:
                client.settimeout(timeout)
            try:
                client.connect(sock_path)
                return client
            except (ConnectionRefusedError, FileNotFoundError):
                client.close()
                if thread is not None and not thread.is_alive():
                    raise AssertionError(
                        "worker exited before the client connected",
                    ) from None
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.02)

    def test_idle_connected_client_does_not_pin_worker(
            self, short_sock_dir, monkeypatch):
        sock_path, thread, box = self._run_worker(
            short_sock_dir, monkeypatch)
        client = self._connect_client(sock_path, thread=thread)
        try:
            # Generous join budget with a structural completion
            # signal: the worker runs in-process with a REAL 1s
            # socket timeout, so under xdist scheduler starvation the
            # timeout wakeup plus the surrounding Python can land
            # seconds late — a tight join deadline measured the
            # scheduler, not the idle enforcement. A worker that
            # MISSES the per-connection timeout never exits at all,
            # so the wide budget loses no detection power; rc == 0 is
            # the idle-exit path's return value (a crashed run() body
            # leaves box empty).
            thread.join(timeout=60)
            assert not thread.is_alive(), (
                "worker still alive with an idle connected client")
            assert box.get("rc") == 0
        finally:
            client.close()

    def test_requests_still_served_under_connection_timeout(
            self, short_sock_dir, monkeypatch):
        import json as json_mod

        # The property here is "requests are served WITH a
        # per-connection timeout armed", not the timeout's length —
        # a 1s timeout raced this test's own client scheduling (the
        # worker idle-exited before a descheduled client sent its
        # ping). 60s keeps the settimeout code path armed while
        # sitting far outside any load stall.
        sock_path, thread, box = self._run_worker(
            short_sock_dir, monkeypatch, idle_timeout=60)
        # Client timeout and join budget both generous: the in-process
        # worker's replies can be scheduled seconds late under load
        # (same rationale as the idle test above).
        client = self._connect_client(sock_path, thread=thread, timeout=60)
        try:
            stream = client.makefile("rwb")
            stream.write(b'{"id": 1, "op": "ping"}\n')
            stream.flush()
            resp = json_mod.loads(stream.readline())
            assert resp == {"id": 1, "ok": True, "pong": True}
            stream.write(b'{"id": 2, "op": "shutdown"}\n')
            stream.flush()
            resp = json_mod.loads(stream.readline())
            assert resp["ok"] is True and resp["bye"] is True
            thread.join(timeout=60)
            assert not thread.is_alive()
            assert box.get("rc") == 0
        finally:
            client.close()


class TestWorkerSocketFdTransport:
    """--socket-fd mode: serve an inherited socketpair half without
    ever calling socket(2)/bind(2) — the transport for sandbox lanes
    whose seccomp policy denies AF_UNIX socket creation to the child.
    No JVM required (ping/shutdown never touch pyghidra)."""

    def _run_worker_fd(self, monkeypatch, fd, idle_timeout=60):
        import threading

        from packages.ghidra import server_worker

        monkeypatch.setattr(
            sys, "argv",
            ["server_worker", "--socket-fd", str(fd),
             "--idle-timeout", str(idle_timeout)],
        )
        box: dict = {}

        def run():
            box["rc"] = server_worker.main()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread, box

    def test_ping_and_shutdown_over_socketpair(self, monkeypatch):
        import json as json_mod
        import socket as socket_mod

        parent, child = socket_mod.socketpair()
        # detach(): the worker's socket.socket(fileno=...) takes
        # ownership of the fd — a second owner in this (in-process)
        # test would double-close it.
        child_fd = child.detach()
        thread, box = self._run_worker_fd(monkeypatch, child_fd)
        try:
            parent.settimeout(60)
            stream = parent.makefile("rwb")
            stream.write(b'{"id": 1, "op": "ping"}\n')
            stream.flush()
            resp = json_mod.loads(stream.readline())
            assert resp == {"id": 1, "ok": True, "pong": True}
            stream.write(b'{"id": 2, "op": "shutdown"}\n')
            stream.flush()
            resp = json_mod.loads(stream.readline())
            assert resp["ok"] is True and resp["bye"] is True
            thread.join(timeout=60)
            assert not thread.is_alive()
            assert box.get("rc") == 0
        finally:
            parent.close()

    def test_peer_eof_exits_zero(self, monkeypatch):
        import socket as socket_mod

        parent, child = socket_mod.socketpair()
        child_fd = child.detach()
        thread, box = self._run_worker_fd(monkeypatch, child_fd)
        parent.close()  # EOF: the parent (only peer) went away
        thread.join(timeout=60)
        assert not thread.is_alive(), "worker did not exit on peer EOF"
        assert box.get("rc") == 0

    def test_exactly_one_transport_required(self, monkeypatch, capsys):
        # Assert the SPECIFIC exclusive-transport refusal (message +
        # argparse exit code), not just any SystemExit — a missing
        # required positional would also exit and make the assertion
        # vacuous.
        from packages.ghidra import server_worker

        monkeypatch.setattr(sys, "argv", ["server_worker"])
        with pytest.raises(SystemExit) as ei:
            server_worker.main()
        assert ei.value.code == 2
        assert ("exactly one of socket_path or --socket-fd"
                in capsys.readouterr().err)
        monkeypatch.setattr(
            sys, "argv",
            ["server_worker", "/tmp/x.sock", "--socket-fd", "7"],
        )
        with pytest.raises(SystemExit) as ei:
            server_worker.main()
        assert ei.value.code == 2
        assert ("exactly one of socket_path or --socket-fd"
                in capsys.readouterr().err)
