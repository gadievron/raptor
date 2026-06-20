"""Stage 3E-b — bound the bare subprocess.run calls in docker_run (RED tests).

behavioral-audit-2026-05-27.md F4: `_logs_tail` (docker logs) and
`_read_allocated_host_port` (docker inspect, per-poll) used bare
`subprocess.run` with NO timeout. A wedged docker daemon makes them hang —
and since these run between SDK messages, no guard fires until the 1440s wall.
Fix: route both through `run_with_timeout` (bounded; never raises).

RED until they use `run_with_timeout`: monkeypatching it is a no-op while the
code still calls `subprocess.run` directly.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from cve_env.tools import docker_run as dr
from cve_env.utils.run import RunOutcome


def test_logs_tail_is_bounded(monkeypatch: Any) -> None:
    seen: dict[str, float] = {}

    def fake_rwt(cmd: list[str], *, timeout: float, **_kw: Any) -> RunOutcome:
        seen["timeout"] = timeout
        return RunOutcome(returncode=None, stdout="", stderr="", timed_out=True)

    monkeypatch.setattr(dr, "run_with_timeout", fake_rwt)
    out = dr._logs_tail("cid")
    assert seen.get("timeout", 0) > 0, (
        "_logs_tail must route through run_with_timeout (bounded), not bare "
        "subprocess.run — a wedged docker daemon would otherwise hang to the wall."
    )
    assert isinstance(out, str)  # best-effort: returns a string even on timeout


def test_read_allocated_host_port_poll_is_bounded(monkeypatch: Any) -> None:
    seen: dict[str, float] = {}

    def fake_rwt(cmd: list[str], *, timeout: float, **_kw: Any) -> RunOutcome:
        seen["timeout"] = timeout
        return RunOutcome(returncode=None, stdout="", stderr="", timed_out=True)

    monkeypatch.setattr(dr, "run_with_timeout", fake_rwt)
    monkeypatch.setattr(
        dr.time, "sleep", lambda *_a, **_k: None
    )  # don't really sleep the poll gap

    start = time.monotonic()
    with pytest.raises(
        dr.RunError
    ):  # never finds a port → no_host_port after the deadline
        dr._read_allocated_host_port("cid", container_port=8080, timeout_s=0.3)
    elapsed = time.monotonic() - start

    assert seen.get("timeout", 0) > 0, (
        "each docker-inspect poll must be bounded via run_with_timeout."
    )
    assert elapsed < 2.0, (
        f"poll loop ran {elapsed:.1f}s — should be bounded by timeout_s (0.3)."
    )
