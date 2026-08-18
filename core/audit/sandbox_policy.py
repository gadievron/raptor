"""Sandbox policy for /audit external tool invocations.

Every external tool invocation in the audit pipeline must go through
the sandbox infrastructure.  This module maps each tool to
its required sandbox profile and provides a dispatch function that
enforces the policy.

Sandbox profiles (from core/sandbox/):
  - run:         full namespace + Landlock + seccomp + network deny
  - run_trusted: Landlock filesystem isolation + resource limits (no namespace)
  - container:   OCI container isolation (for JVM/heavy tools)

The policy is a data table, not a framework.  Callers use
get_sandbox_profile() to look up the profile, then call
core.sandbox.run or core.sandbox.run_trusted directly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


class SandboxProfile:
    FULL = "full"
    TRUSTED = "trusted"
    CONTAINER = "container"
    NONE = "none"


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
}


def get_sandbox_profile(tool: str) -> ToolPolicy | None:
    """Look up the sandbox policy for a tool.

    Returns None for unknown tools — callers should refuse to run
    unregistered tools without an explicit policy.
    """
    return _TOOL_POLICIES.get(tool.lower())


def require_sandbox_profile(tool: str) -> ToolPolicy:
    """Look up the sandbox policy, raising ValueError for unknown tools."""
    policy = get_sandbox_profile(tool)
    if policy is None:
        raise ValueError(
            f"no sandbox policy registered for tool '{tool}' — "
            f"register it in sandbox_policy.py before invocation"
        )
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
})


def validate_all_tools_sandboxed(
    invoked_tools: list[str],
) -> list[str]:
    """Check that every invoked tool has a sandbox policy.

    Returns a list of tools WITHOUT a policy (should be empty).
    LLM-only phases and cost-ledger spend buckets (review,
    checker_synthesis, refinement, iris, etc.) are excluded — they
    don't invoke external tools; subprocess tools enforce their
    policies at the runner chokepoint and never appear in the cost
    ledger this validator is fed from.
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
