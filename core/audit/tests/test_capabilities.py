"""Tests for core.audit.capabilities."""

from unittest.mock import patch

from core.audit.capabilities import (
    AuditCapabilities,
    format_capability_report,
    probe_capabilities,
)


from contextlib import ExitStack, contextmanager
from core.testing.module_bindings import mock_module_attribute
from core.testing.module_state import isolated_module_state


@contextmanager
def _missing_tool_discovery(*args, **kwargs):
    from core.audit import capabilities
    from packages.joern import prereqs

    with ExitStack() as scope:
        scope.enter_context(isolated_module_state(prereqs, {
            "_resolved_joern": None, "_joern_resolved": False,
            "_resolved_joern_parse": None, "_joern_parse_resolved": False,
            "_resolved_java": None, "_java_resolved": False,
        }))
        mocked = scope.enter_context(mock_module_attribute(capabilities, "shutil", "which", *args, **kwargs))
        scope.enter_context(mock_module_attribute(prereqs, "shutil", "which", new=mocked))
        yield mocked



class TestProbeCapabilities:
    def test_returns_dataclass(self):
        caps = probe_capabilities()
        assert isinstance(caps, AuditCapabilities)

    def test_no_binary(self):
        caps = probe_capabilities(binary_path=None)
        assert not caps.binary_available
        assert not caps.dwarf_available

    def test_nonexistent_binary(self, tmp_path):
        caps = probe_capabilities(binary_path=tmp_path / "nope")
        assert not caps.binary_available

    def test_all_tools_missing(self):
        with _missing_tool_discovery(return_value=None) as _mock_which:
            caps = probe_capabilities()
            assert not caps.joern
            assert not caps.r2
            assert not caps.semgrep
            assert not caps.coccinelle
            assert not caps.codeql

    def test_tool_found(self):
        """Joern detected when check_prereqs returns no issues."""
        with patch(
            "packages.joern.prereqs.check_prereqs", return_value=[]
        ):
            caps = probe_capabilities()
        assert caps.joern
        assert caps.joern_issues == ()

    def test_joern_issues_populated(self):
        """joern_issues populated when check_prereqs reports problems."""
        with patch(
            "packages.joern.prereqs.check_prereqs",
            return_value=["java 8 < required 11"],
        ):
            caps = probe_capabilities()
        assert not caps.joern
        assert caps.joern_issues == ("java 8 < required 11",)

    def test_joern_issues_on_import_error(self):
        """joern_issues populated when packages.joern is not importable."""
        import sys
        with patch.dict(
            sys.modules,
            {"packages.joern": None, "packages.joern.prereqs": None},
        ):
            caps = probe_capabilities()
        assert not caps.joern
        assert caps.joern_issues == ("packages.joern not available",)


class TestFormatCapabilityReport:
    def test_all_present(self):
        caps = AuditCapabilities(
            joern=True, r2=True, frida=True,
            semgrep=True, coccinelle=True, codeql=True, ghidra=True,
            binary_available=True, dwarf_available=True,
        )
        report = format_capability_report(caps)
        assert "Joern" in report
        assert "Frida" in report
        assert "unavailable" not in report
        assert "DWARF" in report

    def test_none_present(self):
        caps = AuditCapabilities()
        report = format_capability_report(caps)
        assert "unavailable" in report
        assert "No binary" in report

    def test_partial(self):
        caps = AuditCapabilities(joern=True, semgrep=True)
        report = format_capability_report(caps)
        assert "Joern" in report
        assert "Semgrep" in report
        assert "Frida" in report  # listed as unavailable
        assert "unavailable" in report

    def test_binary_no_dwarf(self):
        caps = AuditCapabilities(binary_available=True, dwarf_available=False)
        report = format_capability_report(caps)
        assert "no DWARF" in report

    def test_joern_issues_surfaced(self):
        caps = AuditCapabilities(
            joern=False,
            joern_issues=("java 8 < required 11",),
        )
        report = format_capability_report(caps)
        assert "java 8 < required 11" in report
        assert "Joern" in report
