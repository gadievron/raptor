"""Tests for core.audit.safe_env."""

from __future__ import annotations

from core.audit.safe_env import (
    ResourceLimits,
    format_limits_summary,
    get_output_limit,
    get_resource_limits,
    truncate_output,
)


class TestResourceLimits:
    def test_known_tool(self):
        limits = get_resource_limits("r2")
        assert limits is not None
        assert limits.timeout_seconds == 120
        assert limits.memory_limit_mb == 2048

    def test_unknown_tool(self):
        assert get_resource_limits("mystery") is None

    def test_case_insensitive(self):
        assert get_resource_limits("R2") is not None

    def test_to_dict(self):
        limits = ResourceLimits(timeout_seconds=30, memory_limit_mb=1024)
        d = limits.to_dict()
        assert d["timeout_seconds"] == 30
        assert d["network_deny"] is True

    def test_joern_has_high_memory(self):
        limits = get_resource_limits("joern")
        assert limits.memory_limit_mb >= 4096

    def test_ghidra_has_long_timeout(self):
        limits = get_resource_limits("ghidra")
        assert limits.timeout_seconds >= 300


class TestOutputLimits:
    def test_joern_query_limit(self):
        limit = get_output_limit("joern_query")
        assert limit is not None
        assert limit.max_results == 100

    def test_strings_limit(self):
        limit = get_output_limit("strings")
        assert limit is not None
        assert limit.max_results == 10000

    def test_unknown(self):
        assert get_output_limit("random_tool") is None


class TestTruncateOutput:
    def test_no_truncation_needed(self):
        items = list(range(50))
        result, note = truncate_output(items, "joern_query")
        assert len(result) == 50
        assert note is None

    def test_truncation_applied(self):
        items = list(range(200))
        result, note = truncate_output(items, "joern_query")
        assert len(result) == 100
        assert note is not None
        assert "100 of 200" in note

    def test_no_limit_configured(self):
        items = list(range(999999))
        result, note = truncate_output(items, "unknown_tool")
        assert len(result) == 999999
        assert note is None


class TestFormatSummary:
    def test_includes_tools(self):
        s = format_limits_summary()
        assert "r2" in s
        assert "joern" in s
        assert "timeout=" in s
