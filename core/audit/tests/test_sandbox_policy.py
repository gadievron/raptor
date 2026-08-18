"""Tests for core.audit.sandbox_policy."""

from __future__ import annotations

import pytest

from core.audit.sandbox_policy import (
    SandboxProfile,
    ToolPolicy,
    all_policies,
    format_sandbox_summary,
    get_sandbox_profile,
    require_sandbox_profile,
    validate_all_tools_sandboxed,
)


class TestGetSandboxProfile:
    def test_known_tool(self):
        policy = get_sandbox_profile("r2")
        assert policy is not None
        assert policy.profile == SandboxProfile.FULL

    def test_trusted_tool(self):
        policy = get_sandbox_profile("readelf")
        assert policy is not None
        assert policy.profile == SandboxProfile.TRUSTED

    def test_unknown_tool(self):
        assert get_sandbox_profile("mystery_tool") is None

    def test_case_insensitive(self):
        policy = get_sandbox_profile("R2")
        assert policy is not None


class TestRequireSandboxProfile:
    def test_known_tool(self):
        policy = require_sandbox_profile("joern")
        assert policy.profile == SandboxProfile.FULL

    def test_unknown_raises(self):
        with pytest.raises(ValueError, match="no sandbox policy"):
            require_sandbox_profile("unknown_tool")


class TestAllPolicies:
    def test_returns_all(self):
        policies = all_policies()
        assert len(policies) >= 10
        tools = {p.tool for p in policies}
        assert "r2" in tools
        assert "joern" in tools
        assert "semgrep" in tools


class TestValidateAllToolsSandboxed:
    def test_all_known(self):
        missing = validate_all_tools_sandboxed(["r2", "joern", "semgrep"])
        assert missing == []

    def test_unknown_tool(self):
        missing = validate_all_tools_sandboxed(["r2", "unknown_tool"])
        assert "unknown_tool" in missing

    def test_empty_list(self):
        assert validate_all_tools_sandboxed([]) == []

    def test_llm_phases_excluded(self):
        missing = validate_all_tools_sandboxed(
            ["review", "checker_synthesis", "error_retry", "re_review"]
        )
        assert missing == []

    def test_summary_phase_excluded(self):
        # The pre-loop LLM summary pass books its spend as a "summary"
        # phase on every budget-governed run — it is LLM-only and must
        # not trip the missing-sandbox-policy warning.
        assert validate_all_tools_sandboxed(["summary"]) == []

    def test_llm_phases_mixed_with_tools(self):
        missing = validate_all_tools_sandboxed(
            ["review", "semgrep", "checker_synthesis", "unknown_tool"]
        )
        assert missing == ["unknown_tool"]


class TestToolPolicy:
    def test_to_dict(self):
        policy = ToolPolicy(
            tool="r2", profile=SandboxProfile.FULL,
            reason="test", memory_limit_mb=2048,
            timeout_seconds=120,
        )
        d = policy.to_dict()
        assert d["tool"] == "r2"
        assert d["profile"] == "full"
        assert d["memory_limit_mb"] == 2048

    def test_to_dict_omits_zero_limits(self):
        policy = ToolPolicy(
            tool="nm", profile=SandboxProfile.TRUSTED,
            reason="test",
        )
        d = policy.to_dict()
        assert "memory_limit_mb" not in d
        assert "timeout_seconds" not in d


class TestPolicyProperties:
    def test_r2_has_memory_limit(self):
        policy = get_sandbox_profile("r2")
        assert policy.memory_limit_mb > 0

    def test_r2_network_deny(self):
        policy = get_sandbox_profile("r2")
        assert policy.network_deny is True

    def test_joern_has_memory_limit(self):
        policy = get_sandbox_profile("joern")
        assert policy.memory_limit_mb >= 4096

    def test_compiler_is_full_sandbox(self):
        policy = get_sandbox_profile("compiler")
        assert policy.profile == SandboxProfile.FULL

    def test_semgrep_is_trusted(self):
        policy = get_sandbox_profile("semgrep")
        assert policy.profile == SandboxProfile.TRUSTED


class TestFormatSummary:
    def test_default_summary(self):
        s = format_sandbox_summary()
        assert "registered" in s

    def test_with_tools_all_covered(self):
        s = format_sandbox_summary(["r2", "joern"])
        assert "all" in s.lower()

    def test_with_missing_tool(self):
        s = format_sandbox_summary(["r2", "unknown"])
        assert "WITHOUT" in s
