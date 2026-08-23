"""RPC-boundary validation tests for netns_coordinator._run_child.

These run WITHOUT a working coordinator substrate (no namespaces
needed) — they exercise the spec-shape validation only, so they are
deliberately not in test_coordinator_isolation.py, which skips the
whole module when the coordinator can't launch on the host.

Pins the fix for spec-shape TypeErrors escaping the try that
populates ``result.error``: a malformed exploit spec crashed the
coordinator with a raw traceback (breaking the JSON-on-stdout
protocol), and a malformed target spec silently killed the target
thread, leaving ``returncode=None`` with no error string.
"""

import io
import json

from core.sandbox import netns_coordinator as _nc


def test_run_child_malformed_spec_sets_structured_error_not_raise():
    for field, bad in (
        ("writable_paths", "/tmp/not-a-list"),
        ("readable_paths", "/tmp/not-a-list"),
        ("etc_overlay", [["/etc/hosts", "/tmp/hosts"]]),
    ):
        spec = {"cmd": ["/bin/true"], field: bad}
        result = _nc._ChildResult()
        _nc._run_child("exploit", spec, result)  # must not raise
        assert result.error is not None, field
        assert "TypeError" in result.error
        assert field in result.error
        # The fail-loud message must still reach the caller through
        # the structured response _emit_response serialises.
        json.dumps(result.to_dict())
        assert result.wallclock_s >= 0.0


def test_run_child_missing_cmd_sets_structured_error():
    result = _nc._ChildResult()
    _nc._run_child("exploit", {"env": {}}, result)  # must not raise
    assert result.error is not None
    assert "KeyError" in result.error
    json.dumps(result.to_dict())


def test_run_child_string_allowed_tcp_ports_sets_structured_error():
    # ``list("80")`` would silently become ['8', '0'] — the RPC
    # boundary must reject a bare string like every other narrowed
    # field, through result.error rather than a raised TypeError.
    for bad in ("80", {"port": 80}, [80, "81"], [True]):
        spec = {"cmd": ["/bin/true"], "allowed_tcp_ports": bad}
        result = _nc._ChildResult()
        _nc._run_child("exploit", spec, result)  # must not raise
        assert result.error is not None, repr(bad)
        assert "TypeError" in result.error, repr(bad)
        assert "allowed_tcp_ports" in result.error, repr(bad)
        json.dumps(result.to_dict())


def test_run_child_valid_allowed_tcp_ports_forwarded(monkeypatch):
    import core.sandbox as _sandbox

    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)

        class _R:
            returncode = 0
            stdout = b""
            stderr = b""

        return _R()

    monkeypatch.setattr(_sandbox, "run", fake_run)
    for good in ([80, 8080], (443,)):
        spec = {"cmd": ["/bin/true"], "allowed_tcp_ports": good}
        result = _nc._ChildResult()
        _nc._run_child("exploit", spec, result)
        assert result.error is None
        assert captured["allowed_tcp_ports"] == list(good)


def test_run_child_default_timeout_matches_main_join_bound(monkeypatch):
    # The leaked-subprocess window is bounded by ``timeout_s + 1.0s``
    # only when main()'s join default is at least _run_child's
    # sandbox-timeout default. Both must resolve to the shared
    # _DEFAULT_CHILD_TIMEOUT_S when the spec omits timeout_s.
    import core.sandbox as _sandbox

    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)

        class _R:
            returncode = 0
            stdout = b""
            stderr = b""

        return _R()

    monkeypatch.setattr(_sandbox, "run", fake_run)
    result = _nc._ChildResult()
    _nc._run_child("exploit", {"cmd": ["/bin/true"]}, result)
    assert result.error is None
    assert captured["timeout"] == _nc._DEFAULT_CHILD_TIMEOUT_S


def _drive_main_hermetic(request, monkeypatch):
    """Drive main() with namespaces and children stubbed out (no forks,
    no privileges needed). Returns (errors, responses, join_timeouts,
    exit_code) — exit_code is None when main() returned normally."""
    errors, responses, join_timeouts = [], [], []

    class FakeThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def join(self, timeout=None):
            join_timeouts.append(timeout)

    monkeypatch.setattr(_nc, "_setup_namespaces", lambda: "test")
    monkeypatch.setattr(_nc.sys, "stdin", io.StringIO(json.dumps(request)))
    monkeypatch.setattr(_nc.threading, "Thread", FakeThread)
    monkeypatch.setattr(_nc, "_run_child", lambda *a, **k: None)
    monkeypatch.setattr(_nc, "_emit_response", responses.append)
    monkeypatch.setattr(
        _nc, "_emit_error",
        lambda reason, message: errors.append((reason, message)),
    )
    exit_code = None
    try:
        _nc.main()
    except SystemExit as exc:
        exit_code = exc.code
    return errors, responses, join_timeouts, exit_code


def test_main_join_bound_uses_shared_default_without_timeout_s(monkeypatch):
    # Drive main() hermetically (no namespaces, no forks): a request
    # whose target spec omits timeout_s must produce a join bound of
    # _DEFAULT_CHILD_TIMEOUT_S + 1.0 — the documented leaked-subprocess
    # bound, aligned with _run_child's sandbox-timeout default. The
    # specs carry an output boundary so the hostile-profile floor
    # (tested below) does not refuse them.
    request = {
        "target": {"cmd": ["/bin/true"], "output": "/tmp/coord-test-out"},
        "exploit": {"cmd": ["/bin/true"], "output": "/tmp/coord-test-out"},
    }
    errors, responses, join_timeouts, exit_code = _drive_main_hermetic(
        request, monkeypatch,
    )
    assert errors == []
    assert exit_code is None
    assert join_timeouts == [_nc._DEFAULT_CHILD_TIMEOUT_S + 1.0]
    assert len(responses) == 1


# --------------------------------------------------------------------------
# Fail-closed isolation floor: a child spec that runs HOSTILE code
# (profile target_run — also the default when a spec omits profile)
# without any filesystem boundary (no target=, no output=) engages no
# mount tree and no Landlock write rule. The coordinator must refuse
# the whole request before either child starts; trusted-tool profiles
# keep their current defaults.
# --------------------------------------------------------------------------


def test_spec_isolation_problem_names_the_unbounded_hostile_spec():
    assert _nc._spec_isolation_problem(
        "target", {"cmd": ["/bin/x"], "profile": "target_run"},
    ) is not None
    # Bare spec: profile defaults to target_run — still hostile.
    assert _nc._spec_isolation_problem("target", {"cmd": ["/bin/x"]}) is not None
    # Either boundary is enough.
    assert _nc._spec_isolation_problem(
        "target",
        {"cmd": ["/bin/x"], "profile": "target_run", "output": "/tmp/o"},
    ) is None
    assert _nc._spec_isolation_problem(
        "target",
        {"cmd": ["/bin/x"], "profile": "target_run", "target": "/tmp/t"},
    ) is None
    # Trusted-tool profiles keep their defaults.
    assert _nc._spec_isolation_problem(
        "exploit", {"cmd": ["/bin/x"], "profile": "frida"},
    ) is None


def test_main_refuses_hostile_target_spec_without_boundary(monkeypatch):
    request = {
        "target": {"cmd": ["/bin/x"], "profile": "target_run"},
        "exploit": {"cmd": ["/bin/x"], "profile": "frida"},
    }
    errors, responses, join_timeouts, exit_code = _drive_main_hermetic(
        request, monkeypatch,
    )
    assert exit_code == 2
    assert responses == []
    assert join_timeouts == [], "no child may start after the refusal"
    assert len(errors) == 1
    reason, message = errors[0]
    assert reason == "unbounded_hostile_spec"
    assert "target" in message
    assert "filesystem boundary" in message


def test_main_refuses_hostile_exploit_spec_without_boundary(monkeypatch):
    request = {
        "target": {
            "cmd": ["/bin/x"], "profile": "target_run",
            "output": "/tmp/coord-test-out",
        },
        "exploit": {"cmd": ["/bin/x"], "profile": "target_run"},
    }
    errors, responses, _joins, exit_code = _drive_main_hermetic(
        request, monkeypatch,
    )
    assert exit_code == 2
    assert responses == []
    assert errors and errors[0][0] == "unbounded_hostile_spec"
    assert "exploit" in errors[0][1]


def test_main_refuses_default_profile_spec_without_boundary(monkeypatch):
    # A spec that omits profile resolves to target_run in _run_child;
    # the floor must treat it as hostile rather than let the default
    # slip through unbounded.
    request = {
        "target": {"cmd": ["/bin/x"]},
        "exploit": {"cmd": ["/bin/x"], "profile": "frida"},
    }
    errors, _responses, _joins, exit_code = _drive_main_hermetic(
        request, monkeypatch,
    )
    assert exit_code == 2
    assert errors and errors[0][0] == "unbounded_hostile_spec"


def test_main_accepts_hostile_spec_with_output_boundary(monkeypatch):
    request = {
        "target": {
            "cmd": ["/bin/x"], "profile": "target_run",
            "output": "/tmp/coord-test-out", "restrict_reads": True,
        },
        "exploit": {
            "cmd": ["/bin/x"], "profile": "target_run",
            "target": "/tmp/coord-test-target",
        },
    }
    errors, responses, _joins, exit_code = _drive_main_hermetic(
        request, monkeypatch,
    )
    assert errors == []
    assert exit_code is None
    assert len(responses) == 1


def test_main_accepts_trusted_tool_spec_without_boundary(monkeypatch):
    # Trusted-tool profiles (the frida attacher, debuggers, ...) keep
    # their current defaults — the floor is scoped to hostile code.
    request = {
        "target": {
            "cmd": ["/bin/x"], "profile": "target_run",
            "output": "/tmp/coord-test-out",
        },
        "exploit": {"cmd": ["/bin/x"], "profile": "frida"},
    }
    errors, responses, _joins, exit_code = _drive_main_hermetic(
        request, monkeypatch,
    )
    assert errors == []
    assert exit_code is None
    assert len(responses) == 1
