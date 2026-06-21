"""S22.4-B1 (2026-05-03): tests for health_constraints derivation +
prompt rendering.

derive_constraints: probe results → ServiceConstraint list (HIGH-confidence
service-degradation only).

format_constraints_for_prompt: ServiceConstraint list → Markdown section
for SYSTEM_PROMPT prefix. Empty input → empty output (no spurious section).
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

from cve_env.agent.health_constraints import (
    ServiceConstraint,
    derive_constraints,
    format_constraints_for_prompt,
)
from cve_env.infra.service_health import HealthResult

def test_derive_empty_when_all_probes_ok() -> None:
    results = [
        HealthResult("DNS resolution", ok=True, latency_ms=50, detail="ok"),
        HealthResult("Docker Hub", ok=True, latency_ms=200, detail="ok"),
        HealthResult("GitHub API", ok=True, latency_ms=100, detail="ok"),
    ]
    assert derive_constraints(results) == []

def test_derive_dh_rate_limit_emits_constraint() -> None:
    results = [
        HealthResult(
            "Docker Hub",
            ok=False,
            latency_ms=3000,
            detail="toomanyrequests: ...",
            rate_limit="rate-limited",
        ),
    ]
    constraints = derive_constraints(results)
    assert len(constraints) == 1
    c = constraints[0]
    assert c.service == "Docker Hub"
    assert c.state == "rate_limited"
    assert "vulhub-image" in c.avoid_methods
    assert "source-build" in c.prefer_methods

def test_derive_only_dh_constraint_at_v1() -> None:
    """v1 of B1 only emits the DH constraint. Other CRITICAL services
    not yet mapped (deferred to a follow-up). NVD/GitHub down would
    halt the bench at preflight, so an in-agent constraint isn't the
    right intervention there anyway."""
    results = [
        HealthResult("GitHub API", ok=False, latency_ms=99999, detail="timeout"),
        HealthResult("NVD API", ok=False, latency_ms=99999, detail="timeout"),
    ]
    assert derive_constraints(results) == []

def test_format_empty_returns_empty_string() -> None:
    """No spurious '## Service health constraints' section when no
    constraints (most runs)."""
    assert format_constraints_for_prompt([]) == ""

def test_format_dh_constraint_renders_avoid_prefer() -> None:
    c = ServiceConstraint(
        service="Docker Hub",
        state="rate_limited",
        avoid_methods=("vulhub-image", "vulhub-compose"),
        prefer_methods=("source-build",),
        reason_text="DH rate-limited; ~6h cooldown.",
    )
    out = format_constraints_for_prompt([c])
    assert "## Service health constraints" in out
    assert "Docker Hub" in out
    assert "rate_limited" in out
    assert "AVOID" in out
    assert "vulhub-image, vulhub-compose" in out
    assert "PREFER" in out
    assert "source-build" in out
    assert "give_up" in out  # guidance about give_up if no PREFER works

def test_build_injects_constraints_into_system_prompt(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """End-to-end: when build() receives constraints, the SYSTEM_PROMPT
    passed to run_agent contains the constraint section. When constraints
    is empty, system_prompt is the original SYSTEM_PROMPT unchanged."""
    import asyncio
    from unittest.mock import patch

    from cve_env.agent.loop import build
    from cve_env.agent.prompts import SYSTEM_PROMPT
    from cve_env.models import CveRecord, HostInfo

    # Capture what run_agent receives
    captured: dict[str, str] = {}

    async def fake_run_agent(*, system_prompt, **kwargs):  # type: ignore[no-untyped-def]
        captured["system_prompt"] = system_prompt
        # Minimal Outcome-shaped result; build() needs SOMETHING terminal
        from cve_env.agent.llm import AgentRunOutcome

        return AgentRunOutcome(stop_reason="end_turn", num_turns=1, total_cost_usd=0.0)

    cve = CveRecord(cve_id="CVE-2024-9999", product="t", version="1.0", description="x")
    host = HostInfo(arch="arm64", os="darwin", rosetta_available=True)

    # Case 1: no constraints → system_prompt = caps_block + SYSTEM_PROMPT
    # (B-20 2026-05-07: caps_block is always prepended; constraints when
    # present prepend in front of caps_block.)
    with patch("cve_env.agent.loop.run_agent", fake_run_agent):
        asyncio.run(build(cve, host, run_id="run-empty", audit_root=tmp_path))
    assert SYSTEM_PROMPT in captured["system_prompt"]
    assert "## Caps for this run" in captured["system_prompt"]
    assert "## Service health constraints" not in captured["system_prompt"]

    # Case 2: with constraint → system_prompt has the constraint section prepended
    captured.clear()
    constraint = ServiceConstraint(
        service="Docker Hub",
        state="rate_limited",
        avoid_methods=("vulhub-image",),
        prefer_methods=("source-build",),
        reason_text="DH down",
    )
    with patch("cve_env.agent.loop.run_agent", fake_run_agent):
        asyncio.run(
            build(
                cve,
                host,
                run_id="run-with-constraint",
                audit_root=tmp_path,
                constraints=[constraint],
            )
        )
    assert "## Service health constraints" in captured["system_prompt"]
    assert "Docker Hub" in captured["system_prompt"]
    assert "AVOID" in captured["system_prompt"]
    # Original SYSTEM_PROMPT also appears (constraint is a PREFIX, not replace)
    assert SYSTEM_PROMPT in captured["system_prompt"]

def test_format_multiple_constraints_separated() -> None:
    c1 = ServiceConstraint(
        service="A",
        state="x",
        avoid_methods=("m1",),
        prefer_methods=("m2",),
        reason_text="r1",
    )
    c2 = ServiceConstraint(
        service="B",
        state="y",
        avoid_methods=("m3",),
        prefer_methods=("m4",),
        reason_text="r2",
    )
    out = format_constraints_for_prompt([c1, c2])
    # Both services + their reasons appear
    assert "A" in out
    assert "B" in out
    assert "r1" in out
    assert "r2" in out
    assert "m1" in out
    assert "m3" in out
