"""Contract tests for core.env.verify — the plan engine over a handle.

The cve_env suite pins the full check-executor behaviour through its
tool surface; these pin the core engine directly: handle wiring, plan
canonicalization, injector semantics, executor-table dispatch, hooks.
"""

from __future__ import annotations

import re
from typing import Any

from core.container.exec import ExecOutcome
from core.env import verify as ev
from core.env.handle import RuntimeHandle

_VERSION_RE = re.compile(r"--version|pip show|dpkg -l")


class FakeHandle(RuntimeHandle):
    tier = "docker"

    def __init__(self, *, running: bool = True, logs: str = "",
                 exec_outcomes: dict[str, ExecOutcome] | None = None,
                 host_port: int = 8080) -> None:
        self._running = running
        self._logs = logs
        self._exec = exec_outcomes or {}
        self._host_port = host_port
        self.torn_down = False

    def endpoint(self):
        return ("127.0.0.1", self._host_port) if self._host_port else None

    def state(self) -> dict[str, Any]:
        if self._running:
            return {"Running": True, "Status": "running"}
        return {"Running": False, "Status": "exited", "ExitCode": 1,
                "OOMKilled": False}

    def logs(self, tail: int = 500) -> str:
        return self._logs

    def exec(self, command: str, *, timeout_seconds: float = 30.0,
             workdir: str = "") -> ExecOutcome:
        return self._exec.get(command, ExecOutcome(
            ok=True, container_id="cid", command=command, exit_code=0,
            stdout="", stderr=""))

    def teardown(self) -> None:
        self.torn_down = True


# ── status / logs / exec through the handle ───────────────────────────


def test_status_pass_and_fail_shapes() -> None:
    ok = ev.check_container_status(FakeHandle(running=True))
    assert ok["passed"] and ok["details"]["status"] == "running"
    bad = ev.check_container_status(FakeHandle(running=False,
                                               logs="traceback ..."))
    assert not bad["passed"]
    assert bad["details"]["logs_tail"].startswith("traceback")
    assert "hint" not in bad["details"]  # no hook → no hint key


def test_status_hint_hook_attaches() -> None:
    hooks = ev.VerifyHooks(status_hint=lambda state, logs: "look here")
    bad = ev.check_container_status(FakeHandle(running=False), hooks=hooks)
    assert bad["details"]["hint"] == "look here"


def test_exec_check_matches_exit_and_stdout() -> None:
    outcome = ExecOutcome(ok=True, container_id="c", command="app --version",
                          exit_code=0, stdout="app 1.2.3", stderr="")
    h = FakeHandle(exec_outcomes={"app --version": outcome})
    r = ev.check_exec(h, command="app --version",
                      expected_stdout_contains="1.2.3")
    assert r["passed"]
    assert r["details"]["expected_stdout_contains"] == "1.2.3"
    r2 = ev.check_exec(h, command="app --version",
                       expected_stdout_contains="9.9")
    assert not r2["passed"]


def test_log_check_regex_and_fetch_failure() -> None:
    h = FakeHandle(logs="Server started on :8080\n")
    assert ev.check_logs(h, expected_patterns=["Server start"])["passed"]
    missing = ev.check_logs(h, expected_patterns=["nope"])
    assert not missing["passed"]
    fetchfail = ev.check_logs(FakeHandle(logs=""),
                              expected_patterns=["x"])
    assert not fetchfail["passed"]
    assert "no logs available" in fetchfail["details"]["error"]


# ── host-ip guard ─────────────────────────────────────────────────────


def test_public_and_metadata_ips_refused() -> None:
    assert ev.assert_local_host_ip("8.8.8.8") is not None
    assert ev.assert_local_host_ip("169.254.169.254") is not None
    assert ev.assert_local_host_ip("example.com") is not None
    assert ev.assert_local_host_ip("127.0.0.1") is None
    assert ev.assert_local_host_ip("10.1.2.3") is None
    assert ev.assert_local_host_ip("::1") is None


# ── plan utilities ────────────────────────────────────────────────────


def test_canonicalize_prepends_status() -> None:
    plan = [{"type": "http_check"}]
    out = ev.canonicalize_plan(plan)
    assert out[0] == {"type": "container_status"}
    assert ev.canonicalize_plan(out) == out  # idempotent


def test_alias_normalization_canonical_wins() -> None:
    out = ev.normalize_kwargs({"timeout": 5, "timeout_seconds": 9},
                              ev.HTTP_KEY_ALIASES)
    assert out == {"timeout_seconds": 9}


def test_version_injector_fills_only_gaps() -> None:
    plan = [
        {"type": "exec_check", "command": "app --version"},
        {"type": "exec_check", "command": "app --version",
         "expected_stdout_contains": "2.0.1"},
        {"type": "exec_check", "command": "echo hi"},
    ]
    out, injected = ev.inject_version_assertion(plan, "1.2.3", _VERSION_RE)
    assert injected == {0}
    assert out[0]["expected_stdout_contains"] == "1.2.3"
    assert out[1]["expected_stdout_contains"] == "2.0.1"
    assert "expected_stdout_contains" not in out[2]
    # No version digits in the literal → no injection.
    _, none_injected = ev.inject_version_assertion(plan, "latest", _VERSION_RE)
    assert none_injected == set()


def test_smoke_injector_appends_only_when_needed() -> None:
    plan = [{"type": "http_check", "path": "/"}]
    out, injected = ev.inject_functional_smoke(plan)
    assert len(out) == 3 and injected == {1, 2}
    # Already smoke-satisfied (content_check) → untouched.
    rich = [{"type": "http_check", "path": "/", "content_check": ["x"]}]
    same, none = ev.inject_functional_smoke(rich)
    assert same == rich and none == set()
    # Non-HTTP plans never get HTTP probes injected.
    db = [{"type": "exec_check", "command": "psql -c 'select 1'"}]
    same2, none2 = ev.inject_functional_smoke(db)
    assert same2 == db and none2 == set()


# ── verify_plan engine ────────────────────────────────────────────────


def test_verify_plan_short_circuits_on_fatal_failure() -> None:
    h = FakeHandle(running=False)
    out = ev.verify_plan(h, [{"type": "log_check",
                              "expected_patterns": ["x"]}])
    assert out["passed"] is False
    assert out["reason"].startswith("container_status")
    assert len(out["results"]) == 1  # log_check never ran


def test_verify_plan_injected_smoke_grades_but_never_gates() -> None:
    calls: list[str] = []

    def http_exec(**kw: Any) -> dict[str, Any]:
        calls.append(kw.get("path", "/"))
        if kw.get("path", "/").startswith("/_phase32"):
            return {"type": "http_check", "passed": False, "reason": "404≠200",
                    "details": {}}
        return {"type": "http_check", "passed": True,
                "details": {"url": kw.get("path", "/")}}

    h = FakeHandle()
    executors = ev.default_executors(h)
    executors["http_check"] = http_exec
    out = ev.verify_plan(plan=[{"type": "container_status"},
                               {"type": "http_check", "path": "/"}],
                         handle=h, executors=executors)
    assert out["passed"] is True  # failing injected probe didn't gate
    smoke = [r for r in out["results"]
             if r.get("injected_source") == "phase32_smoke"]
    assert smoke, "smoke probes were not injected/tagged"


def test_verify_plan_rejects_non_list_and_non_dict_steps() -> None:
    h = FakeHandle()
    assert not ev.verify_plan(h, "[]")["passed"]
    out = ev.verify_plan(h, [{"type": "container_status"}, "nope"])
    assert not out["passed"]
    assert "must be a dict" in out["reason"]


def test_verify_plan_quality_warning_hook() -> None:
    hooks = ev.VerifyHooks(quality_warning=lambda results: "add version")
    out = ev.verify_plan(FakeHandle(), [{"type": "container_status"}],
                         hooks=hooks)
    assert out["passed"] and out["verify_quality_warning"] == "add version"


def test_verify_plan_executor_table_is_authoritative() -> None:
    seen: list[str] = []

    def spy_status() -> dict[str, Any]:
        seen.append("status")
        return {"type": "container_status", "passed": True, "details": {}}

    out = ev.verify_plan(
        plan=[{"type": "container_status"}],
        executors={"container_status": spy_status},
        endpoint=("127.0.0.1", 80),
    )
    assert out["passed"] and seen == ["status"]


def test_verify_plan_requires_handle_or_executors() -> None:
    try:
        ev.verify_plan(plan=[])
    except ValueError as exc:
        assert "handle or an executor table" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


# ── bounded HTTP exchange (the peer runs hostile target code) ─────────


def _serve(handler_cls):
    import socketserver
    import threading

    srv = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_http_exchange_caps_oversize_body() -> None:
    import http.server

    class Big(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 — stdlib handler contract
            payload = b"x" * (256 * 1024)
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):  # noqa: A003
            pass

    srv = _serve(Big)
    try:
        status, content = ev._http_exchange(
            host_ip="127.0.0.1", host_port=srv.server_address[1],
            method="GET", path="/", timeout_seconds=5.0,
            max_response_bytes=64 * 1024,
        )
    finally:
        srv.shutdown()
        srv.server_close()
    assert status == 200
    assert len(content) == 64 * 1024  # capped, not the declared 256 KiB


def test_http_exchange_deadline_stops_dripping_body() -> None:
    import http.server
    import time as _time

    class Drip(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"  # no Content-Length: read-to-EOF body

        def do_GET(self):  # noqa: N802 — stdlib handler contract
            self.send_response(200)
            self.end_headers()
            try:
                for _ in range(200):
                    self.wfile.write(b"y" * 512)
                    self.wfile.flush()
                    _time.sleep(0.2)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):  # noqa: A003
            pass

    srv = _serve(Drip)
    start = _time.monotonic()
    try:
        status, content = ev._http_exchange(
            host_ip="127.0.0.1", host_port=srv.server_address[1],
            method="GET", path="/", timeout_seconds=1.0,
        )
    finally:
        srv.shutdown()
        srv.server_close()
    elapsed = _time.monotonic() - start
    assert status == 200
    # The drip feeds ~512 B per 0.2 s inside the socket-inactivity
    # window; without the wall deadline this read would run ~40 s.
    assert elapsed < 5.0
    assert 0 < len(content) < 200 * 512


def test_http_exchange_watchdog_stops_dripping_headers() -> None:
    """The status/header phase blocks inside http.client with only the
    inactivity timeout; a peer dripping header bytes (reviewer PoC:
    one byte per 0.4 s sustains for hours) must be cut by the
    whole-exchange watchdog, not survive it."""
    import socket as _socket
    import threading as _threading
    import time as _time

    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    stop = _threading.Event()

    def _drip() -> None:
        try:
            conn, _ = srv.accept()
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            # Drip header bytes one at a time, each inside the
            # inactivity window — never a blank line, never EOF.
            for ch in (b"X-Drip: " + b"a" * 4096) * 4:
                if stop.is_set():
                    break
                try:
                    conn.sendall(bytes([ch]))
                except OSError:
                    break
                _time.sleep(0.2)
            conn.close()
        except OSError:
            pass

    t = _threading.Thread(target=_drip, daemon=True)
    t.start()
    start = _time.monotonic()
    try:
        try:
            ev._http_exchange(
                host_ip="127.0.0.1", host_port=port,
                method="GET", path="/", timeout_seconds=1.0,
            )
        except TimeoutError as exc:
            assert "watchdog" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected TimeoutError from header drip")
    finally:
        stop.set()
        srv.close()
    # Watchdog fires at 2x timeout; without it this blocks ~55 min.
    assert _time.monotonic() - start < 5.0
# ── tcp_probe destination pinning (plans are untrusted) ───────────────


def _tcp_spy(seen: list[dict[str, Any]]):
    def spy(**kw: Any) -> dict[str, Any]:
        seen.append(kw)
        return {"type": "tcp_probe_check", "passed": True, "details": {}}
    return spy


def _pin_executors(seen: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "container_status": lambda: {
            "type": "container_status", "passed": True, "details": {}},
        "tcp_probe_check": _tcp_spy(seen),
    }


def test_tcp_probe_plan_host_ip_is_discarded() -> None:
    seen: list[dict[str, Any]] = []
    out = ev.verify_plan(
        plan=[{"type": "tcp_probe_check", "host": "10.11.12.13",
               "host_port": 8080, "send_text": "PING",
               "expected_response_contains": "PONG"}],
        executors=_pin_executors(seen),
        endpoint=("127.0.0.1", 8080),
    )
    assert out["passed"], out
    assert seen and seen[0]["host_ip"] == "127.0.0.1"  # pinned, not 10.x


def test_tcp_probe_port_outside_allowlist_fails_closed() -> None:
    seen: list[dict[str, Any]] = []
    out = ev.verify_plan(
        plan=[{"type": "tcp_probe_check", "host_port": 9999,
               "send_text": "x", "expected_response_contains": "y"}],
        executors=_pin_executors(seen),
        endpoint=("127.0.0.1", 8080),
    )
    assert not out["passed"]
    assert "not a published endpoint" in out["reason"]
    assert seen == []  # probe never dispatched


def test_tcp_probe_allowed_tcp_ports_extends_allowlist() -> None:
    seen: list[dict[str, Any]] = []
    out = ev.verify_plan(
        plan=[{"type": "tcp_probe_check", "host_port": 6379,
               "send_text": "PING", "expected_response_contains": "PONG"}],
        executors=_pin_executors(seen),
        endpoint=("127.0.0.1", 8080),
        allowed_tcp_ports={6379},
    )
    assert out["passed"], out
    assert seen and seen[0]["host_port"] == 6379
