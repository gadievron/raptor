"""Execution-posture tests for the crash analyser's addr2line lane.

addr2line parses the CRASHING binary's ELF/DWARF bytes — fully
attacker-authored input to a parser family (libbfd) with a long CVE
history — so it must run under the full sandbox like the module's
other binutils invocations (readelf/nm/objdump via
``core.binary.inspect``), never with ``run_trusted`` (safe env +
rlimits only, no isolation).

Hermetic: the sandbox spawn is intercepted at ``core.sandbox.run``
(the seam ``core.binary.inspect`` resolves at call time); no tool or
target binary is ever executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from packages.binary_analysis import crash_analyser as ca_mod
from packages.binary_analysis.crash_analyser import CrashAnalyser


def _bare_analyser(binary: Path) -> CrashAnalyser:
    """CrashAnalyser without __init__ side effects (tool probes, nm)."""
    analyser = CrashAnalyser.__new__(CrashAnalyser)
    analyser.binary = binary
    analyser._available_tools = {"addr2line": True}
    return analyser


class TestAddr2lineRunsInsideTheSandbox:
    def test_resolution_uses_full_sandbox_not_run_trusted(
            self, tmp_path, monkeypatch):
        """addr2line must be spawned through the sandboxed inspection
        substrate (network blocked, Landlock-scoped to the binary's
        directory) — the attacker-authored DWARF must never reach an
        unisolated tool process."""
        binary = tmp_path / "crashme"
        binary.write_bytes(b"\x7fELF")
        analyser = _bare_analyser(binary)

        sandbox_calls: list[tuple[list[str], dict[str, Any]]] = []

        def fake_sandbox_run(argv: list[str], **kwargs: Any) -> MagicMock:
            sandbox_calls.append((argv, kwargs))
            return MagicMock(
                returncode=0,
                stdout="parse_header\n/src/parser.c:42\n",
                stderr="",
            )

        def refuse_run_trusted(*args: Any, **kwargs: Any) -> None:
            msg = "addr2line ran OUTSIDE the sandbox (run_trusted)"
            raise AssertionError(msg)

        monkeypatch.setattr("core.sandbox.run", fake_sandbox_run)
        monkeypatch.setattr(ca_mod, "_run_trusted", refuse_run_trusted)

        function, file_line = analyser._resolve_address_with_addr2line(
            "0x401000")

        assert function == "parse_header"
        assert file_line == "/src/parser.c:42"
        assert len(sandbox_calls) == 1
        argv, kwargs = sandbox_calls[0]
        assert argv[0] == "addr2line"
        assert argv[-1] == "0x401000"
        assert str(binary.resolve()) in argv
        assert kwargs["block_network"] is True
        assert kwargs["target"] == str(binary.resolve().parent)

    def test_unavailable_tool_short_circuits_without_spawn(
            self, tmp_path, monkeypatch):
        binary = tmp_path / "crashme"
        binary.write_bytes(b"\x7fELF")
        analyser = _bare_analyser(binary)
        analyser._available_tools = {"addr2line": False}

        def refuse_any_spawn(*args: Any, **kwargs: Any) -> None:
            msg = "no subprocess may spawn when addr2line is unavailable"
            raise AssertionError(msg)

        monkeypatch.setattr("core.sandbox.run", refuse_any_spawn)
        monkeypatch.setattr(ca_mod, "_run_trusted", refuse_any_spawn)

        assert analyser._resolve_address_with_addr2line("0x401000") == (
            "unknown", "unknown")

    def test_invalid_address_never_reaches_the_tool(
            self, tmp_path, monkeypatch):
        binary = tmp_path / "crashme"
        binary.write_bytes(b"\x7fELF")
        analyser = _bare_analyser(binary)

        def refuse_any_spawn(*args: Any, **kwargs: Any) -> None:
            msg = "unvalidated address must not reach addr2line"
            raise AssertionError(msg)

        monkeypatch.setattr("core.sandbox.run", refuse_any_spawn)
        monkeypatch.setattr(ca_mod, "_run_trusted", refuse_any_spawn)

        for bad in ("--help", "@resp", "0x12<x>", "not-an-address"):
            assert analyser._resolve_address_with_addr2line(bad) == (
                "unknown", "unknown")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
