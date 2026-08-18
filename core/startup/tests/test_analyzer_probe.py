"""Tests for the compiler-analyzer / z3 capability probes in
``core.startup.init._check_analyzer_capabilities`` (P35b).

The compiler channel's silent absence degraded /audit recall
invisibly; the probe surfaces it in both banner and doctor via the
shared check_env parts/warnings shape. All compiler probes are
stubbed — no subprocesses run.
"""

from __future__ import annotations

from unittest.mock import patch

from core.startup.init import _check_analyzer_capabilities


class TestAnalyzerProbe:
    def test_gcc_analyzer_reported(self):
        with patch(
            "core.audit.compiler_sweep._gcc_analyzer",
            return_value=("/usr/bin/gcc", "sarif-file"),
        ), patch(
            "core.audit.compiler_sweep._clang_path", return_value=None,
        ):
            parts, warnings = _check_analyzer_capabilities()
        assert "analyzer ✓ (gcc -fanalyzer)" in parts
        assert not any("analyzer" in w for w in warnings)

    def test_clang_fallback_reported(self):
        with patch(
            "core.audit.compiler_sweep._gcc_analyzer", return_value=None,
        ), patch(
            "core.audit.compiler_sweep._clang_path",
            return_value="/usr/bin/clang",
        ):
            parts, warnings = _check_analyzer_capabilities()
        assert "analyzer ✓ (clang --analyze)" in parts
        assert not any("analyzer" in w for w in warnings)

    def test_missing_analyzer_warns_without_failure_part(self):
        with patch(
            "core.audit.compiler_sweep._gcc_analyzer", return_value=None,
        ), patch(
            "core.audit.compiler_sweep._clang_path", return_value=None,
        ):
            parts, warnings = _check_analyzer_capabilities()
        # Degrades — warning only, never a ✗ part (doctor treats ✗
        # env parts as failures).
        assert not any("analyzer" in p for p in parts)
        assert any(
            "compiler-analyzer corroboration limited" in w
            for w in warnings
        )

    def test_probe_failure_never_raises(self):
        with patch(
            "core.audit.compiler_sweep._gcc_analyzer",
            side_effect=RuntimeError("probe exploded"),
        ):
            parts, warnings = _check_analyzer_capabilities()
        assert isinstance(parts, list)
        assert isinstance(warnings, list)

    def test_z3_version_reported_when_installed(self):
        with patch(
            "core.audit.compiler_sweep._gcc_analyzer",
            return_value=("/usr/bin/gcc", "json"),
        ), patch(
            "core.audit.compiler_sweep._clang_path", return_value=None,
        ), patch(
            "importlib.metadata.version", return_value="4.13.0.0",
        ):
            parts, _ = _check_analyzer_capabilities()
        assert "z3 4.13.0.0 ✓" in parts

    def test_z3_absent_no_part(self):
        from importlib.metadata import PackageNotFoundError

        with patch(
            "core.audit.compiler_sweep._gcc_analyzer",
            return_value=("/usr/bin/gcc", "json"),
        ), patch(
            "core.audit.compiler_sweep._clang_path", return_value=None,
        ), patch(
            "importlib.metadata.version",
            side_effect=PackageNotFoundError("z3-solver"),
        ):
            parts, warnings = _check_analyzer_capabilities()
        assert not any(p.startswith("z3 ") for p in parts)
        # Presence warning is TOOL_DEPS' job — no duplicate here.
        assert not any("z3" in w for w in warnings)

    def test_check_env_includes_capability_parts(self, monkeypatch):
        """check_env threads the capability parts through (banner and
        doctor both consume check_env output)."""
        from core.startup import init as startup_init

        with patch(
            "core.startup.init._check_analyzer_capabilities",
            return_value=(["analyzer ✓ (gcc -fanalyzer)"], ["cap warn"]),
        ):
            parts, warnings = startup_init.check_env(set())
        assert "analyzer ✓ (gcc -fanalyzer)" in parts
        assert "cap warn" in warnings
