"""Register-conditioned feasibility context in the crash exploit bundle."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict

from packages.llm_analysis.crash_agent import (
    _build_crash_exploit_bundle,
    _crash_feasibility_summary,
)


@dataclass
class FakeCrashContext:
    crash_id: str = "crash-001"
    binary_path: Path = Path("/nonexistent/test_binary")
    input_file: Path = Path("/dev/null")
    signal: str = "11"
    registers: Dict[str, str] = field(default_factory=lambda: {
        "rip": "0x41414141", "rsp": "0x7fff0000",
    })
    crash_type: str = "format_string"
    exploitability: str = "exploitable"
    cvss_estimate: float = 7.5
    function_name: str = "vuln_func"
    crash_address: str = "0x41414141"
    analysis: Dict = field(default_factory=dict)


def _real_binary(tmp_path: Path) -> Path:
    p = tmp_path / "bin"
    p.write_bytes(b"\x7fELF")
    return p


_FEAS_RESULT = {
    "verdict": "likely_exploitable",
    "blockers": ["full RELRO"],
    "suggestions": ["target partial overwrite"],
    "exploitation_paths": {
        "format_string_vuln": {
            "verdict": "DIFFICULT",
            "analysis": {
                "one_gadget_info": {
                    "smt_feasibility": {
                        "feasible": False,
                        "conditioned_on_crash_state": True,
                        "unsatisfied_constraints": ["rsp & 0xf == 0"],
                        "model": {},
                        "reasoning": "r",
                    },
                },
            },
        },
    },
}


class TestFeasibilitySummary:
    def test_no_registers_skips(self, tmp_path):
        ctx = FakeCrashContext(
            binary_path=_real_binary(tmp_path), registers={},
        )
        assert _crash_feasibility_summary(ctx) is None

    def test_missing_binary_skips(self):
        assert _crash_feasibility_summary(FakeCrashContext()) is None

    def test_crash_state_forwarded_and_summarised(self, tmp_path, monkeypatch):
        seen = {}

        def fake_analyze(binary, vuln_type=None, crash_state=None, **kw):
            seen["binary"] = binary
            seen["vuln_type"] = vuln_type
            seen["crash_state"] = crash_state
            return _FEAS_RESULT

        import packages.exploit_feasibility.api as api
        monkeypatch.setattr(api, "analyze_binary", fake_analyze)
        ctx = FakeCrashContext(binary_path=_real_binary(tmp_path))
        summary = _crash_feasibility_summary(ctx)
        assert seen["crash_state"] == ctx.registers
        assert seen["vuln_type"] == "format_string"
        assert summary["verdict"] == "likely_exploitable"
        og = summary["exploitation_paths"]["format_string_vuln"][
            "one_gadget_smt"]
        assert og["feasible"] is False
        assert og["conditioned_on_crash_state"] is True

    def test_analysis_failure_degrades_to_none(self, tmp_path, monkeypatch):
        import packages.exploit_feasibility.api as api

        def boom(*a, **kw):
            raise RuntimeError("readelf missing")

        monkeypatch.setattr(api, "analyze_binary", boom)
        ctx = FakeCrashContext(binary_path=_real_binary(tmp_path))
        assert _crash_feasibility_summary(ctx) is None


class TestExploitBundleBlock:
    def test_block_present_when_feasibility_available(
        self, tmp_path, monkeypatch,
    ):
        import packages.exploit_feasibility.api as api
        monkeypatch.setattr(api, "analyze_binary",
                            lambda *a, **kw: _FEAS_RESULT)
        input_file = tmp_path / "input"
        input_file.write_bytes(b"A" * 8)
        ctx = FakeCrashContext(
            binary_path=_real_binary(tmp_path), input_file=input_file,
        )
        bundle = _build_crash_exploit_bundle(ctx)
        user = next(m.content for m in bundle.messages if m.role == "user")
        assert 'kind="binary-feasibility"' in user
        assert "conditioned_on_crash_state" in user

    def test_block_absent_without_registers(self, tmp_path):
        input_file = tmp_path / "input"
        input_file.write_bytes(b"A" * 8)
        ctx = FakeCrashContext(
            binary_path=_real_binary(tmp_path),
            input_file=input_file,
            registers={},
        )
        bundle = _build_crash_exploit_bundle(ctx)
        user = next(m.content for m in bundle.messages if m.role == "user")
        assert 'kind="binary-feasibility"' not in user
