"""Tests for the persistent sandboxed Ghidra server."""

import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

from packages.ghidra.detect import pyghidra_available


@pytest.fixture
def short_sock_dir():
    """AF_UNIX-safe socket dir (same pattern as core/sandbox tests).

    ``tmp_path`` under xdist / deep TMPDIRs exceeds sun_path (~108
    bytes on Linux) once a socket name is appended — bind() then
    fails with "AF_UNIX path too long".
    """
    d = tempfile.mkdtemp(prefix="raptor-sk-", dir="/tmp")
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


class TestServerGating:
    def test_requires_pyghidra(self, tmp_path, monkeypatch):
        import packages.ghidra.server as server_mod
        monkeypatch.setattr(
            server_mod, "pyghidra_available", lambda: False,
        )
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        with pytest.raises(server_mod.GhidraServerError, match="pyghidra"):
            server_mod.GhidraServer(gpr)

    def test_persist_requires_start(self, tmp_path, monkeypatch):
        import packages.ghidra.server as server_mod
        monkeypatch.setattr(
            server_mod, "pyghidra_available", lambda: True,
        )
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        srv = server_mod.GhidraServer(gpr)
        with pytest.raises(server_mod.GhidraServerError, match="not started"):
            srv.persist_enriched(tmp_path / "out")


class TestWorkerProtocol:
    """Worker protocol logic without a JVM (unknown op, bad JSON)."""

    def test_unknown_op_rejected(self):
        from packages.ghidra import server_worker
        session = server_worker._Session()
        with pytest.raises(RuntimeError, match="unknown op"):
            server_worker._handle(session, {"op": "frobnicate"})

    def test_ops_require_open_project(self):
        from packages.ghidra import server_worker
        session = server_worker._Session()
        with pytest.raises(RuntimeError, match="no project open"):
            server_worker._handle(
                session, {"op": "decompile", "function": "main"},
            )


@pytest.mark.integration
@pytest.mark.skipif(
    not pyghidra_available(), reason="pyghidra not installed",
)
class TestServerLive:
    """Full boot→open→decompile against a real project.

    Marked integration (deselected by default): builds a Ghidra
    project via analyzeHeadless (~15s JVM import) then exercises the
    sandboxed server end to end.
    """

    def test_boot_open_decompile_apply(self, tmp_path):
        import shutil as _shutil
        import subprocess
        headless = _shutil.which("analyzeHeadless")
        if headless is None:
            pytest.skip("analyzeHeadless not on PATH")
        proj_dir = tmp_path / "proj"
        proj_dir.mkdir()
        # Full analysis (no -noanalysis): function definitions are
        # what the decompile assertion needs, and /bin/true is tiny.
        r = subprocess.run(
            [headless, str(proj_dir), "probe",
             "-import", "/bin/true"],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            pytest.skip(f"project build failed: {r.stderr[-200:]}")

        from packages.ghidra.server import GhidraServer
        with GhidraServer(proj_dir / "probe.gpr") as srv:
            info = srv.open()
            assert info["programs"]
            programs = srv.list_programs()
            assert programs == info["programs"]
            code = srv.decompile("entry")
            assert "(" in code
            applied = srv.apply_enrichments({
                "comments": [{"function": "entry", "kind": "plate",
                              "text": "RAPTOR: live test"}],
                "bookmarks": [],
            })
            assert applied["comments"] == 1
            kept = srv.persist_enriched(tmp_path / "keep")
        assert kept.exists()


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

    def test_single_thread_serves_every_op(self):
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

        server_worker._handle = _record
        try:
            handler.run({"op": "ping"})
            handler.run({"op": "ping"})
            handler.run({"op": "ping"})
        finally:
            server_worker._handle = orig
        assert len(seen) == 1
        assert _threading.get_ident() not in seen

    def test_decompile_deadline_tracks_request_timeout(self, monkeypatch):
        from packages.ghidra import server_worker
        seen = {}
        handler = server_worker._HandlerThread(server_worker._Session())

        class _Probe:
            def set(self):
                pass

            def wait(self, timeout=None):
                seen["deadline"] = timeout
                return True  # pretend completion; box empty → KeyError

        monkeypatch.setattr(
            server_worker.threading, "Event", _Probe,
        )
        monkeypatch.setattr(
            server_worker, "_handle",
            lambda session, req: __import__("time").sleep(5),
        )
        try:
            handler.run(
                {"op": "decompile", "function": "f", "timeout": 120},
            )
        except KeyError:
            pass
        assert seen["deadline"] == 135  # request timeout + 15


class TestServerDied:
    """Client-side death detection and restart — no JVM required."""

    def _server(self, tmp_path, monkeypatch):
        import packages.ghidra.server as server_mod
        monkeypatch.setattr(
            server_mod, "pyghidra_available", lambda: True,
        )
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        return server_mod.GhidraServer(gpr)

    def _wire(self, srv, response_line: bytes):
        """Attach a scripted in-memory transport."""
        import io

        class _Stream(io.BytesIO):
            def __init__(self, reply):
                super().__init__()
                self._reply = reply

            def write(self, data):
                return len(data)

            def flush(self):
                pass

            def readline(self, limit=-1):
                return self._reply

        srv._stream = _Stream(response_line)

    def test_worker_exiting_response_raises_died(
        self, tmp_path, monkeypatch,
    ):
        import json as _json

        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch)
        self._wire(srv, (_json.dumps({
            "id": 1, "ok": False, "worker_exiting": True,
            "error": "worker watchdog: op 'decompile' exceeded 45s",
        }) + "\n").encode())
        with pytest.raises(server_mod.GhidraServerDied, match="watchdog"):
            srv._request({"op": "decompile", "function": "f"})

    def test_closed_connection_raises_died(self, tmp_path, monkeypatch):
        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch)
        self._wire(srv, b"")
        with pytest.raises(server_mod.GhidraServerDied, match="restart"):
            srv._request({"op": "ping"})

    def test_plain_error_stays_server_error(self, tmp_path, monkeypatch):
        import json as _json

        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch)
        self._wire(srv, (_json.dumps({
            "id": 1, "ok": False, "error": "function not found: f",
        }) + "\n").encode())
        with pytest.raises(server_mod.GhidraServerError) as ei:
            srv._request({"op": "decompile", "function": "f"})
        assert not isinstance(ei.value, server_mod.GhidraServerDied)

    def test_restart_reboots_and_reopens(self, tmp_path, monkeypatch):
        srv = self._server(tmp_path, monkeypatch)
        srv._work_dir = tmp_path
        srv._work_gpr = tmp_path / "copy.gpr"
        srv._work_gpr.write_text("")
        srv._opened_program = "prog"
        stale_lock = tmp_path / "copy.lock"
        stale_lock.write_text("")
        calls = []
        monkeypatch.setattr(
            srv, "_boot", lambda: calls.append("boot"),
        )
        monkeypatch.setattr(
            srv, "open", lambda: calls.append("open"),
        )
        srv.restart()
        assert calls == ["boot", "open"]
        assert not stale_lock.exists()

    def test_restart_skips_open_when_never_opened(
        self, tmp_path, monkeypatch,
    ):
        srv = self._server(tmp_path, monkeypatch)
        srv._work_dir = tmp_path
        srv._work_gpr = tmp_path / "copy.gpr"
        srv._work_gpr.write_text("")
        calls = []
        monkeypatch.setattr(
            srv, "_boot", lambda: calls.append("boot"),
        )
        monkeypatch.setattr(
            srv, "open", lambda: calls.append("open"),
        )
        srv.restart()
        assert calls == ["boot"]

    def test_restart_refuses_live_worker(self, tmp_path, monkeypatch):
        import threading as _threading

        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch)
        srv._work_dir = tmp_path
        srv._work_gpr = tmp_path / "copy.gpr"
        srv._work_gpr.write_text("")
        stop = _threading.Event()
        srv._thread = _threading.Thread(target=stop.wait, daemon=True)
        srv._thread.start()
        monkeypatch.setattr(
            server_mod, "_SHUTDOWN_GRACE_S", 0.1, raising=True,
        )
        try:
            with pytest.raises(
                server_mod.GhidraServerError, match="still running",
            ):
                srv.restart()
        finally:
            stop.set()

    def test_restart_requires_start(self, tmp_path, monkeypatch):
        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch)
        with pytest.raises(server_mod.GhidraServerError, match="not started"):
            srv.restart()


class TestSubfolderPrograms:
    """Folder-qualified program names — no JVM required."""

    class _File:
        def __init__(self, name, content="ProgramDB"):
            self._name, self._content = name, content

        def getName(self):
            return self._name

        def getContentType(self):
            return self._content

    class _Folder:
        def __init__(self, files=(), folders=()):
            self._files, self._folders = files, folders

        def getFiles(self):
            return list(self._files)

        def getFolders(self):
            return list(self._folders)

        def getName(self):
            return self._name

    def _tree(self):
        sub = self._Folder(files=[self._File("nested")])
        sub._name = "lib"
        deep = self._Folder(files=[self._File("deepest")])
        deep._name = "inner"
        mid = self._Folder(folders=[deep])
        mid._name = "outer"
        return self._Folder(
            files=[self._File("main")], folders=[sub, mid],
        )

    def test_worker_walk_includes_subfolders(self):
        from packages.ghidra import server_worker
        got = server_worker._Session._walk_programs(self._tree())
        assert got == ["main", "lib/nested", "outer/inner/deepest"]

    def test_headless_process_args_split_folder(self):
        from packages.ghidra.headless import _project_process_args
        assert _project_process_args("proj", None) == (
            "proj", ["-process"],
        )
        assert _project_process_args("proj", "main") == (
            "proj", ["-process", "main"],
        )
        assert _project_process_args("proj", "lib/sub/prog") == (
            "proj/lib/sub", ["-process", "prog"],
        )


class TestProgramNameValidation:
    """Attacker-derived program names must never become switches."""

    def test_headless_rejects_suspicious_names(self):
        from packages.ghidra.headless import (
            GhidraError,
            _project_process_args,
        )
        for bad in ("-deleteProject", "sub/-recursive", "a//b",
                    "../escape", "sub/../up"):
            with pytest.raises(GhidraError, match="suspicious"):
                _project_process_args("proj", bad)

    def test_server_open_rejects_suspicious_names(
        self, tmp_path, monkeypatch,
    ):
        import packages.ghidra.server as server_mod
        monkeypatch.setattr(
            server_mod, "pyghidra_available", lambda: True,
        )
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        srv = server_mod.GhidraServer(gpr, program_name="-okToDelete")
        with pytest.raises(server_mod.GhidraServerError, match="suspicious"):
            srv.open()


class TestRestartBudget:
    def test_budget_exhaustion_refuses(self, tmp_path, monkeypatch):
        import packages.ghidra.server as server_mod
        monkeypatch.setattr(
            server_mod, "pyghidra_available", lambda: True,
        )
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        srv = server_mod.GhidraServer(gpr)
        srv._work_dir = tmp_path
        srv._work_gpr = tmp_path / "copy.gpr"
        srv._work_gpr.write_text("")
        monkeypatch.setattr(srv, "_boot", lambda: None)
        for _ in range(server_mod._MAX_RESTARTS):
            srv.restart()
        with pytest.raises(
            server_mod.GhidraServerError, match="restart budget",
        ):
            srv.restart()

    def test_stopped_server_refuses_restart(self, tmp_path, monkeypatch):
        import packages.ghidra.server as server_mod
        monkeypatch.setattr(
            server_mod, "pyghidra_available", lambda: True,
        )
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        srv = server_mod.GhidraServer(gpr)
        work = tmp_path / "work"
        work.mkdir()
        srv._work_dir = work
        srv._work_gpr = work / "copy.gpr"
        srv.stop()
        assert srv._work_dir is None  # stop() nulls state
        with pytest.raises(
            server_mod.GhidraServerError, match="not started",
        ):
            srv.restart()


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


class TestServerTransportSelection:
    """Boot-time transport pre-flight: pathname primary, inherited
    socketpair on hosts whose sandboxed child cannot create AF_UNIX
    sockets. Uses the REAL worker in a plain subprocess (the sandbox
    call is replaced by a pass_fds-honouring spawn) — no JVM."""

    @staticmethod
    def _fake_sandbox_run(cmd, **kwargs):
        import subprocess
        return subprocess.run(
            cmd,
            pass_fds=kwargs.get("pass_fds") or (),
            capture_output=True, text=True,
            timeout=kwargs.get("timeout"),
        )

    def _server(self, tmp_path, monkeypatch, *, capable):
        import core.sandbox as sandbox_pkg
        import packages.ghidra.server as server_mod
        monkeypatch.setattr(
            server_mod, "pyghidra_available", lambda: True,
        )
        monkeypatch.setattr(
            server_mod, "check_child_unix_sockets_available",
            lambda: capable,
        )
        monkeypatch.setattr(
            server_mod, "prepare_working_copy",
            lambda gpr, wd: wd / "copy.gpr",
        )
        monkeypatch.setattr(sandbox_pkg, "run", self._fake_sandbox_run)
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        return server_mod.GhidraServer(gpr, lifetime_s=60)

    def test_pathname_transport_when_capable(self, tmp_path, monkeypatch):
        srv = self._server(tmp_path, monkeypatch, capable=True)
        srv.start()
        try:
            assert srv._child_sock is None  # never created
            assert list(srv._work_dir.glob("worker-*.sock"))
            assert srv._request({"op": "ping"}).get("pong") is True
        finally:
            srv.stop()

    def test_socketpair_transport_when_incapable(
        self, tmp_path, monkeypatch,
    ):
        srv = self._server(tmp_path, monkeypatch, capable=False)
        srv.start()
        try:
            # No pathname socket anywhere; the adopted socketpair
            # serves requests. The child half stays with its owning
            # _serve thread for the worker's whole life (an early
            # close would free the fd number while a spawn could
            # still be in flight).
            assert not list(srv._work_dir.glob("worker-*.sock"))
            assert srv._child_sock is not None
            assert srv._sock is not None
            assert srv._request({"op": "ping"}).get("pong") is True
        finally:
            srv.stop()
        # stop() joins the _serve thread, whose finally releases the
        # child half — worker death surfaces as EOF, no fd leak.
        assert srv._child_sock is None

    def test_boot_failure_releases_child_sock(
        self, tmp_path, monkeypatch,
    ):
        # The owning _serve thread's finally releases the child half
        # once its sandbox call has returned; start()'s failure path
        # joins the thread via stop(), so the release is observable
        # here.
        import core.sandbox as sandbox_pkg
        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch, capable=False)

        def _dead_run(cmd, **kwargs):
            from types import SimpleNamespace
            return SimpleNamespace(returncode=1, stderr="boom: bad worker")

        monkeypatch.setattr(sandbox_pkg, "run", _dead_run)
        with pytest.raises(
            server_mod.GhidraServerError, match="died during boot",
        ):
            srv.start()
        assert srv._child_sock is None

    def test_boot_timeout_keeps_child_fd_valid_for_inflight_spawn(
        self, tmp_path, monkeypatch,
    ):
        # Boot-deadline expiry while the _serve thread is still
        # PRE-spawn: any cleanup-path close of the child half would
        # free the fd number, and a reused descriptor would ride into
        # pass_fds in its place. The fd observed at spawn time must
        # still be the socketpair half.
        import os
        import stat as stat_mod
        import threading as threading_mod

        import core.sandbox as sandbox_pkg
        import packages.ghidra.server as server_mod

        srv = self._server(tmp_path, monkeypatch, capable=False)
        monkeypatch.setattr(server_mod, "_BOOT_TIMEOUT_S", 0.3)
        monkeypatch.setattr(server_mod, "_SHUTDOWN_GRACE_S", 1)
        release = threading_mod.Event()
        seen: dict = {}

        def _slow_spawn_run(cmd, **kwargs):
            release.wait(timeout=30)
            fd = (kwargs.get("pass_fds") or (None,))[0]
            try:
                seen["is_sock"] = stat_mod.S_ISSOCK(
                    os.fstat(fd).st_mode,
                )
            except OSError as e:
                seen["error"] = str(e)
            from types import SimpleNamespace
            return SimpleNamespace(returncode=0, stderr="")

        monkeypatch.setattr(sandbox_pkg, "run", _slow_spawn_run)
        with pytest.raises(
            server_mod.GhidraServerError, match="did not come up",
        ):
            srv.start()
        release.set()
        thread = srv._thread
        assert thread is not None
        thread.join(timeout=30)
        assert not thread.is_alive()
        assert "error" not in seen, seen
        assert seen.get("is_sock") is True
        # ... and the owner released the half once its call returned.
        assert srv._child_sock is None

    def test_boot_response_flood_fails_closed(
        self, tmp_path, monkeypatch,
    ):
        # A hostile worker that floods the pair without a newline
        # must fail the boot at the response cap, not grow the boot
        # buffer without bound.
        import socket as socket_mod
        import threading as threading_mod
        import time as time_mod

        import packages.ghidra.server as server_mod

        srv = self._server(tmp_path, monkeypatch, capable=False)
        monkeypatch.setattr(server_mod, "_MAX_RESPONSE_BYTES", 4096)
        parent, peer = socket_mod.socketpair()
        stop_flood = threading_mod.Event()

        def flood():
            junk = b"x" * 4096
            try:
                while not stop_flood.is_set():
                    peer.sendall(junk)
            except OSError:
                pass

        flooder = threading_mod.Thread(target=flood, daemon=True)
        flooder.start()
        try:
            with pytest.raises(
                server_mod.GhidraServerError,
                match="boot response exceeded",
            ):
                srv._boot_wait_socketpair(
                    parent, time_mod.monotonic() + 15,
                )
        finally:
            stop_flood.set()
            parent.close()
            peer.close()
            flooder.join(timeout=10)
            assert not flooder.is_alive()

    def test_pathname_eperm_death_names_seccomp_policy(
        self, tmp_path, monkeypatch,
    ):
        """The signature that motivated the fallback: a nested-sandbox
        host kills the worker's bind(2) with EPERM. When the pre-flight
        wrongly picked the pathname transport anyway, the boot error
        must attribute the death to the sandbox socket policy instead
        of surfacing a bare traceback."""
        import core.sandbox as sandbox_pkg
        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch, capable=True)

        def _eperm_run(cmd, **kwargs):
            from types import SimpleNamespace
            return SimpleNamespace(
                returncode=1,
                stderr=("PermissionError: [Errno 1] "
                        "Operation not permitted"),
            )

        monkeypatch.setattr(sandbox_pkg, "run", _eperm_run)
        with pytest.raises(
            server_mod.GhidraServerError,
            match="denies AF_UNIX socket creation",
        ) as ei:
            srv.start()
        assert "pre-flight" in str(ei.value)
