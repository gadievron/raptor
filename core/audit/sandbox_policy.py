"""Sandbox policy reference table for /audit external tools.

Advisory reference data, not an enforcement layer: this module maps
each external tool the audit pipeline can invoke to its recommended
sandbox profile and resource limits.  Enforcement happens in
core.sandbox at the spawn layer — tool runners call core.sandbox.run
/ run_trusted directly and do not consult this table on that path.
The require_* helpers below are available as a policy-backed hard
gate, but no production runner is currently wired through them; the
one production consumer is validate_all_tools_sandboxed, a post-run
reporting check fed cost-ledger phase names.

Sandbox profiles (from core/sandbox/):
  - run:         full namespace + Landlock + seccomp + network deny
  - run_trusted: Landlock filesystem isolation + resource limits (no namespace)
  - container:   OCI container isolation (for JVM/heavy tools)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# No NONE profile: every registered tool carries an isolation tier —
# an unsandboxed tier would contradict the containment-floor doctrine
# ("never none") and nothing ever referenced one.
class SandboxProfile:
    FULL = "full"
    TRUSTED = "trusted"
    CONTAINER = "container"


@dataclass(frozen=True)
class ToolPolicy:
    """Sandbox policy for one external tool."""

    tool: str
    profile: str
    reason: str
    memory_limit_mb: int = 0
    timeout_seconds: int = 0
    network_deny: bool = True
    fs_read_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tool": self.tool,
            "profile": self.profile,
            "reason": self.reason,
            "network_deny": self.network_deny,
            "fs_read_only": self.fs_read_only,
        }
        if self.memory_limit_mb:
            d["memory_limit_mb"] = self.memory_limit_mb
        if self.timeout_seconds:
            d["timeout_seconds"] = self.timeout_seconds
        return d


_TOOL_POLICIES: dict[str, ToolPolicy] = {
    "readelf": ToolPolicy(
        tool="readelf", profile=SandboxProfile.TRUSTED,
        reason="binutils parsing attacker-controlled ELF headers",
        timeout_seconds=30,
    ),
    "nm": ToolPolicy(
        tool="nm", profile=SandboxProfile.TRUSTED,
        reason="binutils parsing attacker-controlled symbol tables",
        timeout_seconds=30,
    ),
    "strings": ToolPolicy(
        tool="strings", profile=SandboxProfile.TRUSTED,
        reason="binutils scanning attacker-controlled binary content",
        timeout_seconds=30,
    ),
    "objdump": ToolPolicy(
        tool="objdump", profile=SandboxProfile.TRUSTED,
        reason="disassembly of attacker-controlled instructions",
        timeout_seconds=60,
    ),
    "c++filt": ToolPolicy(
        tool="c++filt", profile=SandboxProfile.TRUSTED,
        reason="demangling attacker-controlled symbol names",
        timeout_seconds=10,
    ),
    "r2": ToolPolicy(
        tool="r2", profile=SandboxProfile.FULL,
        reason="complex binary analysis engine parsing attacker-controlled binaries",
        timeout_seconds=120,
        memory_limit_mb=2048,
    ),
    "joern": ToolPolicy(
        tool="joern", profile=SandboxProfile.FULL,
        reason="JVM application building CPG from attacker-controlled source",
        timeout_seconds=300,
        memory_limit_mb=4096,
    ),
    "joern_server": ToolPolicy(
        tool="joern_server", profile=SandboxProfile.FULL,
        reason="persistent Joern server processing attacker-controlled queries",
        timeout_seconds=0,
        memory_limit_mb=4096,
    ),
    "frida": ToolPolicy(
        tool="frida", profile=SandboxProfile.FULL,
        reason="dynamic instrumentation executing in target process",
        timeout_seconds=60,
        memory_limit_mb=1024,
    ),
    "semgrep": ToolPolicy(
        tool="semgrep", profile=SandboxProfile.TRUSTED,
        reason="tree-sitter parsing + pattern matching on attacker-controlled source",
        timeout_seconds=120,
    ),
    "coccinelle": ToolPolicy(
        tool="coccinelle", profile=SandboxProfile.FULL,
        reason="C parser processing attacker-controlled source",
        timeout_seconds=120,
    ),
    "codeql": ToolPolicy(
        tool="codeql", profile=SandboxProfile.FULL,
        reason="database build from attacker-controlled source (compilation step)",
        timeout_seconds=600,
        memory_limit_mb=4096,
    ),
    "compiler": ToolPolicy(
        tool="compiler", profile=SandboxProfile.FULL,
        reason="compilation of attacker-controlled source — highest risk",
        timeout_seconds=300,
        memory_limit_mb=2048,
    ),
    "ghidra": ToolPolicy(
        tool="ghidra", profile=SandboxProfile.FULL,
        reason="decompiler processing attacker-controlled binaries",
        timeout_seconds=300,
        memory_limit_mb=4096,
    ),
    "php": ToolPolicy(
        tool="php", profile=SandboxProfile.FULL,
        reason=(
            "interpreter executing grammar-validated sanitizer chains "
            "extracted from attacker-controlled source (sanwit witness)"
        ),
        timeout_seconds=30,
        memory_limit_mb=256,
    ),
}


def get_sandbox_profile(tool: str) -> ToolPolicy | None:
    """Look up the sandbox policy for a tool.

    Returns None for unknown tools.  Advisory lookup only — nothing
    is refused based on this result; isolation is enforced by
    core.sandbox at the spawn layer.
    """
    return _TOOL_POLICIES.get(tool.lower())


def require_sandbox_profile(tool: str) -> ToolPolicy:
    """Look up the sandbox policy, raising ValueError for unknown tools.

    Available for callers that want a hard policy gate; currently no
    production runner is wired through it.
    """
    policy = get_sandbox_profile(tool)
    if policy is None:
        msg = (
            f"no sandbox policy registered for tool '{tool}' — "
            f"register it in sandbox_policy.py before invocation"
        )
        raise ValueError(msg)
    return policy


def all_policies() -> list[ToolPolicy]:
    """Return all registered tool policies."""
    return list(_TOOL_POLICIES.values())


_LLM_PHASES = frozenset({
    "review", "checker_synthesis", "error_retry", "re_review",
    # Pre-loop LLM summary extraction (core.audit.llm_summaries),
    # booked into the phase ledger as the "summary" call class.
    "summary",
    # Remaining LLM-side ledger names. The orchestrator feeds this
    # validator the COST-LEDGER phase keys, and that ledger books LLM
    # spend classes exclusively — subprocess tools never book cost
    # there (their runners enforce sandboxing at the invocation
    # chokepoint instead). Every name the ledger can carry is
    # therefore LLM-side by construction: the cost tracker's known
    # phases plus any telemetry call class book_unbooked_classes
    # imports (spec_inference, iris, glance_batch, audit, the
    # "unclassified" fallback…). A live run warned "invoked without
    # policy: refinement, iris, unclassified" — three LLM spend
    # buckets, zero subprocesses; pure false positives.
    "refinement", "spec_inference", "iris", "glance_batch", "audit",
    "unclassified", "concept_discovery", "rule_refinement", "stress",
    "triage", "prefilter", "clean_check", "sweep", "synthesis",
    "dynamic", "reachability", "propagation", "attacker_synthesis",
    "dark_verify", "report", "deepen", "study",
    # On-demand checker synthesis books its own call class; a resumed
    # segment books the prior segments' spend as a pseudo-phase.
    # Both are ledger rows, not tool invocations (each warned as an
    # "unsandboxed tool" on a live run).
    "checker_synthesis_ondemand", "prior_segments",
    # Pass-ledger phase names the orchestrator books directly
    # (``_phase(...)`` / ``start_phase(...)`` literals) — prep stages,
    # post-loop passes, and resolution sweeps. Same construction
    # argument as above: ledger rows, never tool invocations (a live
    # run's finalize warned on every one of these as an "unsandboxed
    # tool"). The closure test enumerates the orchestrator's literals
    # so a new phase name cannot silently re-open the advisory noise.
    "adversarial_refute", "auto_synthesize_rules",
    "confidence_propagation", "flow_trace_review", "iterative_re_review",
    "live_sink_requeue", "post_deepen_sweep", "post_loop_checks",
    "prep_artifact_import", "prep_capability_probe",
    "prep_channel_prepasses", "prep_consistency_prepass",
    "prep_context_map", "prep_context_sets", "prep_edge_pass",
    "prep_evidence_index", "prep_fail_open_census", "prep_finalize",
    "prep_gap_compute", "prep_gap_scoring", "prep_iris_specs",
    "prep_lifecycle_channels", "prep_macro_recovery",
    "prep_mechanical_detectors", "prep_peer_groups", "prep_taint_passes",
    "prep_triage", "resolve_gate_demoted", "sweep_promotion",
    # Direct per-call ledger mints (``cost_tracker.record_call``
    # literals) that no pass-ledger phase name covers: the IRIS
    # refinement health-gate skip marker, the tier-1 edge-contract
    # review class, and the adversarial-refuter pass.
    "adversarial", "edge_review", "iris_refinement_skipped",
})


def validate_all_tools_sandboxed(
    invoked_tools: list[str],
) -> list[str]:
    """Advisory post-run report: ledger names without a policy entry.

    NOT an enforcement gate, and structurally unable to observe a
    real unsandboxed tool: the orchestrator feeds this COST-LEDGER
    phase names, and subprocess tools never book cost there — their
    isolation is enforced at the core.sandbox spawn layer.  All this
    can flag is a ledger spend class missing from the _LLM_PHASES
    allowlist (historically false positives; see the list's inline
    notes).  Returns the names without a policy.
    """
    missing = []
    for tool in invoked_tools:
        if tool in _LLM_PHASES:
            continue
        if get_sandbox_profile(tool) is None:
            missing.append(tool)
    return missing


def format_sandbox_summary(
    invoked_tools: list[str] | None = None,
) -> str:
    """Render a summary of sandbox coverage."""
    if invoked_tools is None:
        policies = all_policies()
        return (
            f"Sandbox policy: {len(policies)} tools registered "
            f"({sum(1 for p in policies if p.profile == SandboxProfile.FULL)} full, "
            f"{sum(1 for p in policies if p.profile == SandboxProfile.TRUSTED)} trusted)"
        )

    missing = validate_all_tools_sandboxed(invoked_tools)
    if missing:
        return (
            f"Sandbox: {len(missing)} tools WITHOUT policy: "
            f"{', '.join(missing)}"
        )
    return f"Sandbox: all {len(invoked_tools)} invoked tools have policies"
