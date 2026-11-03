"""Tests for the persistent sandboxed Ghidra server."""

import os
import shutil
import subprocess
import sys
import tempfile
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






class TestServerTransportSelection:
    """Boot-time transport pre-flight: pathname primary, inherited
    socketpair on hosts whose sandboxed child cannot create AF_UNIX
    sockets. Uses the REAL worker in a plain subprocess (the sandbox
    call is replaced by a pass_fds-honouring spawn) — no JVM."""

    @pytest.fixture(autouse=True)
    def _short_socket_workdirs(self, short_sock_dir, monkeypatch):
        """Keep transport choice independent of the runner's TMPDIR length."""
        from types import SimpleNamespace

        import packages.ghidra.server as server_mod

        fixture_root = short_sock_dir.resolve()
        # Patch the consumer binding, leaving shared tempfile users alone.
        tempfiles = SimpleNamespace(
            mkdtemp=lambda **kw: tempfile.mkdtemp(**{**kw, "dir": str(fixture_root)}),
        )
        with monkeypatch.context() as scoped:
            scoped.setattr(server_mod, "tempfile", tempfiles)
            yield

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
        # The denial memo is process-level state: an earlier test (or
        # any earlier boot in this worker process) that observed the
        # EPERM signature would otherwise steer THIS test's transport
        # selection.
        monkeypatch.setattr(
            server_mod, "_PATHNAME_TRANSPORT_DENIED", False,
        )
        monkeypatch.setattr(sandbox_pkg, "run", self._fake_sandbox_run)
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        return server_mod.GhidraServer(gpr, lifetime_s=60)

    def test_pathname_transport_when_capable(self, tmp_path, monkeypatch):
        srv = self._server(tmp_path, monkeypatch, capable=True)
        self._check_pathname_transport(srv)

    def test_long_socket_path_uses_socketpair(self, tmp_path, monkeypatch):
        srv = self._server(tmp_path, monkeypatch, capable=True)
        # Exercise selection without starting a subprocess or requiring
        # a filesystem that accepts this deliberately overlong path.
        srv._work_dir = tmp_path / ("x" * 110)
        transports = []
        monkeypatch.setattr(srv, "_boot_transport",
                            lambda *, use_pathname: transports.append(use_pathname))
        srv._boot()
        assert transports == [False]

    @staticmethod
    def _check_pathname_transport(srv):
        srv.start()
        try:
            assert srv._child_sock is None  # never created
            sockets = list(srv._work_dir.glob("worker-*.sock"))
            assert sockets
            assert all(len(os.fsencode(path)) <= 103 for path in sockets)
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

    def test_pathname_eperm_boot_falls_back_to_socketpair(
        self, tmp_path, monkeypatch,
    ):
        """The live defect: the host pre-flight predicts the pathname
        transport, but the per-call sandbox lane denies socket(AF_UNIX)
        and the worker dies at socket setup with EPERM. The boot must
        recover on the inherited-socketpair transport instead of
        failing the server (and losing server-resolved reading)."""
        import core.sandbox as sandbox_pkg
        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch, capable=True)
        calls: list = []

        def _lane_denied_run(cmd, **kwargs):
            calls.append(list(cmd))
            if "--socket-fd" in cmd:
                # The inherited descriptor works on the denying lane.
                return self._fake_sandbox_run(cmd, **kwargs)
            from types import SimpleNamespace
            return SimpleNamespace(
                returncode=1,
                stderr=("PermissionError: [Errno 1] "
                        "Operation not permitted"),
            )

        monkeypatch.setattr(sandbox_pkg, "run", _lane_denied_run)
        srv.start()
        try:
            assert len(calls) == 2
            assert "--socket-fd" not in calls[0]
            assert "--socket-fd" in calls[1]
            assert srv._request({"op": "ping"}).get("pong") is True
            # ... and the denial is memoised for the process so the
            # next server boot skips the doomed pathname attempt.
            assert server_mod._PATHNAME_TRANSPORT_DENIED is True
        finally:
            srv.stop()

    def test_denial_memo_boots_socketpair_directly(
        self, tmp_path, monkeypatch,
    ):
        import core.sandbox as sandbox_pkg
        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch, capable=True)
        monkeypatch.setattr(
            server_mod, "_PATHNAME_TRANSPORT_DENIED", True,
        )
        calls: list = []

        def _recording_run(cmd, **kwargs):
            calls.append(list(cmd))
            return self._fake_sandbox_run(cmd, **kwargs)

        monkeypatch.setattr(sandbox_pkg, "run", _recording_run)
        srv.start()
        try:
            assert len(calls) == 1
            assert "--socket-fd" in calls[0]
            assert srv._request({"op": "ping"}).get("pong") is True
        finally:
            srv.stop()

    def test_pathname_eperm_death_names_seccomp_policy(
        self, tmp_path, monkeypatch,
    ):
        """The denial signature raises the typed socket-denial error
        with policy attribution (pathname transport only), and a boot
        whose socketpair retry ALSO dies still surfaces a boot death
        after exactly one retry."""
        import core.sandbox as sandbox_pkg
        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch, capable=True)

        srv._result = {"stderr": ("PermissionError: [Errno 1] "
                                  "Operation not permitted")}
        err = srv._boot_death_error(pathname=True)
        assert isinstance(err, server_mod.GhidraWorkerSocketDenied)
        assert "denies AF_UNIX socket creation" in str(err)
        # The socketpair transport never creates a socket — an EPERM
        # there is NOT the socket-policy signature.
        err = srv._boot_death_error(pathname=False)
        assert not isinstance(err, server_mod.GhidraWorkerSocketDenied)
        srv._result = {}

        calls: list = []

        def _eperm_run(cmd, **kwargs):
            calls.append(list(cmd))
            from types import SimpleNamespace
            return SimpleNamespace(
                returncode=1,
                stderr=("PermissionError: [Errno 1] "
                        "Operation not permitted"),
            )

        monkeypatch.setattr(sandbox_pkg, "run", _eperm_run)
        with pytest.raises(
            server_mod.GhidraServerError, match="died during boot",
        ):
            srv.start()
        assert len(calls) == 2  # pathname attempt + socketpair retry
        assert "--socket-fd" in calls[1]
        assert server_mod._PATHNAME_TRANSPORT_DENIED is True

    def test_non_eperm_boot_death_does_not_retry(
        self, tmp_path, monkeypatch,
    ):
        """Denial-signature selectivity: a pathname boot that dies
        WITHOUT the EPERM signature (e.g. a JVM crash) is a plain
        boot death — no typed denial, no socketpair retry, and the
        process-level denial memo stays untouched."""
        import core.sandbox as sandbox_pkg
        import packages.ghidra.server as server_mod
        srv = self._server(tmp_path, monkeypatch, capable=True)

        jvm_crash = ('Exception in thread "main" '
                     "java.lang.OutOfMemoryError: Java heap space")
        srv._result = {"stderr": jvm_crash}
        err = srv._boot_death_error(pathname=True)
        assert not isinstance(err, server_mod.GhidraWorkerSocketDenied)
        srv._result = {}

        calls: list = []

        def _jvm_crash_run(cmd, **kwargs):
            calls.append(list(cmd))
            from types import SimpleNamespace
            return SimpleNamespace(returncode=1, stderr=jvm_crash)

        monkeypatch.setattr(sandbox_pkg, "run", _jvm_crash_run)
        with pytest.raises(
            server_mod.GhidraServerError, match="died during boot",
        ) as excinfo:
            srv.start()
        assert not isinstance(
            excinfo.value, server_mod.GhidraWorkerSocketDenied,
        )
        assert len(calls) == 1  # exactly one attempt — no retry
        assert "--socket-fd" not in calls[0]
        assert server_mod._PATHNAME_TRANSPORT_DENIED is False


@pytest.mark.wall_budget(40)
def test_worker_cases_in_private_process(tmp_path):
    # One child session amortizes pytest startup across all worker cases.
    # A larger budget than the individual IPC cases allows startup under CI
    # load; the 30s child timeout still bounds broken startup or shutdown.
    root = Path(__file__).resolve().parents[3]
    env = {
        "PATH": os.defpath,
        "HOME": str(tmp_path / "home"),
        "TMPDIR": str(tmp_path),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "RAPTOR_DIR": str(root),
        "RAPTOR_OUT_DIR": str(tmp_path / "out"),
        "RAPTOR_REGISTRY_HOME": str(tmp_path / "registry"),
        "_RAPTOR_TRUSTED": "1",
    }
    for name, value in os.environ.items():
        if name in {"CI", "RAPTOR_TEST_EMULATE_PLATFORM", "RAPTOR_RANDOMISE_TESTS",
                    "RAPTOR_MAX_TEST_SECONDS"} or name.startswith(("COV_CORE_", "COVERAGE_")):
            env[name] = value
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-m", "pytest", "-q", "-o", "addopts=",
             "--import-mode=importlib", "-p", "no:cacheprovider",
             "--basetemp", str(tmp_path / "child-pytest"),
             str(Path(__file__).with_name("worker_server_cases.py"))],
            env=env, cwd=root, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        output = "".join(part.decode("utf-8", "replace") if isinstance(part, bytes)
                         else part or "" for part in (exc.stdout, exc.stderr))
        pytest.fail("Ghidra worker cases timed out:\n" + output)
    assert result.returncode == 0, result.stdout + result.stderr
