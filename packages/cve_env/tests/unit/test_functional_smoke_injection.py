"""Phase 32 — runtime functional-smoke injection (parallel to Phase 24B).

The Phase 48 functional-smoke heuristic at `_smoke.has_functional_smoke`
returns False unless the agent's verify plan satisfies one of:
  * ≥3 active-class checks (http_payload/exec/tcp_payload)
  * ≥1 http_check with content_check_performed=True
  * ≥2 distinct http_check paths

In Phase 25 bench, the agent often issues only 1 http_check → demoted to
`verified_partial` even when verify_passed=True. Phase 24B closed CF-3
for version-assertion; Phase 32 closes the symmetric Phase 48 gap by
injecting smoke probes when the agent's plan misses the threshold.

Injector signature:

    _inject_functional_smoke(plan, host_ip, host_port)
        -> tuple[list[dict], set[int]]

Returns the (potentially modified) plan + the set of indices whose
checks were APPENDED (caller tags those for audit visibility:
`expected_stdout_contains_source`-style `injected_source: "phase32_smoke"`).

Per Phase 21.1 / 26.1 / 24B.1 / 32.1 pattern: xfail(strict=True) RED →
markers removed atomically when 32.4 lands.
"""

from __future__ import annotations


def _try_import():
    try:
        from cve_env.tools.verify import _inject_functional_smoke

        return _inject_functional_smoke
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# RED tests via xfail(strict=True). Removed atomically by Stage 32.4.
# ---------------------------------------------------------------------------


def test_inject_smoke_appends_when_single_http_check_no_content():
    """Single http_check w/o content_check → injector appends extras."""
    inject = _try_import()
    assert inject is not None
    plan = [
        {"type": "container_status"},
        {"type": "http_check", "path": "/", "expected_status": 200},
    ]
    new_plan, injected = inject(plan, host_ip="127.0.0.1", host_port=8080)
    assert len(injected) >= 1, "expected ≥1 appended check"
    # Original 2 entries preserved at start
    assert new_plan[0] == {"type": "container_status"}
    assert new_plan[1] == {"type": "http_check", "path": "/", "expected_status": 200}


def test_inject_smoke_no_op_when_three_actives_present():
    """≥3 active-class checks already → smoke heuristic satisfied, no injection."""
    inject = _try_import()
    assert inject is not None
    plan = [
        {"type": "container_status"},
        {"type": "exec_check", "command": "echo a"},
        {"type": "exec_check", "command": "echo b"},
        {"type": "http_request_check", "url": "/exploit", "payload": "x"},
    ]
    new_plan, injected = inject(plan, host_ip="127.0.0.1", host_port=8080)
    assert injected == set(), f"expected no injection, got {injected}"
    assert new_plan == plan


def test_inject_smoke_no_op_when_two_distinct_http_paths():
    """≥2 distinct http_check paths already → smoke heuristic satisfied."""
    inject = _try_import()
    assert inject is not None
    plan = [
        {"type": "http_check", "path": "/", "expected_status": 200},
        {"type": "http_check", "path": "/about", "expected_status": 200},
    ]
    new_plan, injected = inject(plan, host_ip="127.0.0.1", host_port=8080)
    assert injected == set()


def test_inject_smoke_no_op_when_http_with_content_check_present():
    """http_check with content_check field already → heuristic satisfied via content path."""
    inject = _try_import()
    assert inject is not None
    plan = [
        {
            "type": "http_check",
            "path": "/",
            "expected_status": 200,
            "content_check": "<html",
        },
    ]
    new_plan, injected = inject(plan, host_ip="127.0.0.1", host_port=8080)
    assert injected == set()


def test_inject_smoke_no_op_when_no_http_check():
    """Plan has only exec_check / log_check (non-HTTP service) — don't add
    HTTP probes blindly. Injector is HTTP-specific."""
    inject = _try_import()
    assert inject is not None
    plan = [
        {"type": "exec_check", "command": "dpkg -l libssl"},
        {"type": "log_check", "patterns": ["ready"]},
    ]
    new_plan, injected = inject(plan, host_ip="127.0.0.1", host_port=8080)
    assert injected == set()


def test_inject_smoke_empty_plan_passthrough():
    """Empty plan → empty result. No crash."""
    inject = _try_import()
    assert inject is not None
    new_plan, injected = inject([], host_ip="127.0.0.1", host_port=8080)
    assert new_plan == []
    assert injected == set()
