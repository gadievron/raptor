"""Tests for core.audit.degradation."""

from __future__ import annotations

from core.audit.degradation import (
    DegradationReport,
    TriageSignalAvailability,
    assess_degradation,
    format_capabilities_table,
    format_degradation_report,
    get_fallback,
)


class TestFallback:
    def test_known_tool(self):
        fb = get_fallback("joern")
        assert fb is not None
        assert fb.fallback_tool == "tree-sitter + LLM"

    def test_unknown_tool(self):
        assert get_fallback("mystery") is None

    def test_case_insensitive(self):
        assert get_fallback("R2") is not None

    def test_to_dict(self):
        fb = get_fallback("frida")
        assert fb is not None
        d = fb.to_dict()
        assert d["tool"] == "frida"
        assert "fallback_tool" in d
        assert "impact" in d

    def test_all_major_tools_have_fallbacks(self):
        for tool in ["joern", "frida", "r2", "binary", "semgrep",
                      "coccinelle", "codeql", "ghidra", "dwarf", "cxxfilt"]:
            assert get_fallback(tool) is not None, f"missing fallback for {tool}"


class TestAssessDegradation:
    def test_all_available(self):
        caps = {"joern": True, "r2": True, "frida": True}
        report = assess_degradation(caps)
        assert len(report.available) == 3
        assert len(report.degraded) == 0

    def test_some_degraded(self):
        caps = {"joern": True, "r2": False, "frida": False}
        report = assess_degradation(caps)
        assert "joern" in report.available
        assert len(report.degraded) == 2
        assert any(f.tool == "r2" for f in report.degraded)

    def test_unknown_tool_unavailable(self):
        caps = {"joern": True, "custom_tool": False}
        report = assess_degradation(caps)
        assert "custom_tool" in report.unavailable_no_fallback

    def test_to_dict(self):
        caps = {"joern": True, "r2": False}
        report = assess_degradation(caps)
        d = report.to_dict()
        assert "available" in d
        assert "degraded" in d
        assert len(d["degraded"]) == 1


class TestFormatReport:
    def test_all_available(self):
        report = DegradationReport(available=["joern", "r2", "frida"])
        s = format_degradation_report(report)
        assert "Available:" in s
        assert "joern" in s

    def test_degraded(self):
        fb = get_fallback("joern")
        report = DegradationReport(degraded=[fb])
        s = format_degradation_report(report)
        assert "Degraded" in s
        assert "joern" in s
        assert "tree-sitter" in s

    def test_unavailable(self):
        report = DegradationReport(unavailable_no_fallback=["custom"])
        s = format_degradation_report(report)
        assert "Unavailable" in s
        assert "custom" in s

    def test_combined(self):
        fb = get_fallback("r2")
        report = DegradationReport(
            available=["joern"],
            degraded=[fb],
            unavailable_no_fallback=["custom"],
        )
        s = format_degradation_report(report)
        assert "Available:" in s
        assert "Degraded" in s
        assert "Unavailable" in s


class TestCapabilitiesTable:
    def test_markdown_format(self):
        caps = {"joern": True, "r2": False, "frida": True}
        s = format_capabilities_table(caps)
        assert "| Tool |" in s
        assert "| joern | Yes |" in s
        assert "| r2 | No |" in s
        assert "objdump" in s or "r2" in s

    def test_fallback_shown(self):
        caps = {"joern": False}
        s = format_capabilities_table(caps)
        assert "tree-sitter" in s


class TestTriageSignalAvailability:
    def test_full_availability(self):
        tsa = TriageSignalAvailability(
            joern_reachability=True,
            binary_oracle=True,
            layer0_findings=True,
        )
        defaults = tsa.conservative_defaults()
        assert defaults["on_reachable_path"] is None
        assert defaults["binary_present"] is None

    def test_no_joern(self):
        tsa = TriageSignalAvailability(joern_reachability=False)
        defaults = tsa.conservative_defaults()
        assert defaults["on_reachable_path"] is True

    def test_no_binary_oracle(self):
        tsa = TriageSignalAvailability(binary_oracle=False)
        defaults = tsa.conservative_defaults()
        assert defaults["binary_present"] is True

    def test_summary(self):
        tsa = TriageSignalAvailability(
            joern_reachability=True,
            binary_oracle=False,
        )
        s = tsa.summary()
        assert "Joern reachability" in s
        assert "Binary oracle" in s
        assert "conservative" in s
