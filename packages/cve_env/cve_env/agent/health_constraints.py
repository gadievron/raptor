"""doctor → agent constraint plumbing.

cve-env doctor knows about external-service degradation (Docker Hub
rate-limited, GitHub auth required, etc.). Without this plumbing the agent
does not — it would try a method, hit the failure, and retry in a loop.

This module bridges the gap: derive ServiceConstraint records from
HealthResult probes; format them as a SYSTEM_PROMPT prefix that tells
the agent which ACQUIRE methods to AVOID and which to PREFER for the
current run.

The derivation is conservative: only constraints with HIGH confidence
of impact get emitted. Slow / transient probes don't trigger a constraint
(only structural-fail signals like rate-limit / auth-required do).
"""
from __future__ import annotations

from dataclasses import dataclass

from cve_env.infra.service_health import HealthResult, run_all


@dataclass(frozen=True)
class ServiceConstraint:
    """A single guidance item for the agent based on doctor probes.

    avoid_methods + prefer_methods refer to the 6 ACQUIRE method names
    used elsewhere in the codebase (vulhub-image, vulhub-compose,
    custom-dockerfile, plugin-overlay, source-build, forge-cascade).
    """

    service: str
    state: str
    avoid_methods: tuple[str, ...]
    prefer_methods: tuple[str, ...]
    reason_text: str


# Constraints emitted when specific (service, state) combos appear in
# the probe results. Keep the set small + principled — each entry is
# a documented engine-impact mapping.

_DH_RATE_LIMITED = ServiceConstraint(
    service="Docker Hub",
    state="rate_limited",
    avoid_methods=("vulhub-image", "vulhub-compose", "custom-dockerfile"),
    # source-build's base image MAY also be on DH; if cached locally
    # it works. plugin-overlay has the same conditional. The agent
    # uses 'PREFER' as a hint, not a guarantee — cascade still applies.
    prefer_methods=("source-build", "plugin-overlay"),
    reason_text=(
        "Docker Hub rate-limited (anon limit hit; ~6h cooldown). New "
        "image pulls from Docker Hub will fail with 'toomanyrequests'. "
        "Locally-cached images / non-Docker-Hub registries (quay.io, "
        "ghcr.io) work fine."
    ),
)


def derive_constraints(results: list[HealthResult]) -> list[ServiceConstraint]:
    """Map a list of HealthResults to a list of ServiceConstraints.

    Returns empty list when no constraints apply (clean preflight).
    """
    constraints: list[ServiceConstraint] = []
    for r in results:
        if r.name == "Docker Hub" and r.rate_limit == "rate-limited":
            constraints.append(_DH_RATE_LIMITED)
    return constraints


def probe_for_constraints() -> list[ServiceConstraint]:
    """Run all health probes + derive constraints. Non-cached convenience
    entry point for cli.py:_cmd_build."""
    return derive_constraints(run_all())


def format_constraints_for_prompt(constraints: list[ServiceConstraint]) -> str:
    """Render constraints as a Markdown section for SYSTEM_PROMPT.

    Returns empty string when constraints is empty (no spurious section).
    Otherwise returns a section starting with `## Service health constraints`
    and listing each constraint's avoid/prefer/reason.
    """
    if not constraints:
        return ""
    lines: list[str] = ["## Service health constraints (this run)", ""]
    for c in constraints:
        lines.append(f"**{c.service} — {c.state}.** {c.reason_text}")
        lines.append(f"- AVOID these ACQUIRE methods: {', '.join(c.avoid_methods)}")
        lines.append(f"- PREFER: {', '.join(c.prefer_methods)}")
        lines.append(
            "- If you would otherwise use an AVOID method, treat "
            "it as unavailable and pivot."
        )
        lines.append(
            "- If no PREFER method works for the CVE, give_up with "
            "reason that includes the constraint."
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
