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
