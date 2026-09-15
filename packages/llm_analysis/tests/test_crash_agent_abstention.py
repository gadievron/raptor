"""Crash-agent verdict honesty on abstained LLM analyses.

Response validation nulls a missing/malformed ``is_exploitable`` — an
abstention, not a verdict. ``analyse_crash`` must not coerce that
None into the definitive ``"not_exploitable"`` string on the crash
context / crash report surface; the honest value is the dataclass's
``"unknown"``. Explicit booleans keep their definitive mapping, and
exploit generation still gates on the exact ``"exploitable"`` string
in every case.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.binary_analysis.crash_analyser import CrashContext  # noqa: E402
from packages.llm_analysis.crash_agent import CrashAnalysisAgent  # noqa: E402


class _FakeLLM:
    """Minimal generate_structured stub returning a fixed analysis."""

    def __init__(self, analysis: dict) -> None:
        self._analysis = analysis

    def generate_structured(self, *, prompt, schema, system_prompt=None,
                            task_type=None):
        return dict(self._analysis), "reasoning text"


def _agent(tmp_path: Path, analysis: dict) -> CrashAnalysisAgent:
    agent = object.__new__(CrashAnalysisAgent)
    agent.binary = Path("/bin/true")
    agent.out_dir = tmp_path
    agent.llm = _FakeLLM(analysis)
    agent.llm_config = None
    return agent


def _ctx(tmp_path: Path) -> CrashContext:
    f = tmp_path / "crash-input"
    f.write_bytes(b"AAAA")
    return CrashContext(
        crash_id="crash-001",
        binary_path=Path("/bin/true"),
        input_file=f,
        signal="11",
    )


def _analysis(is_exploitable) -> dict:
    return {
        "is_true_positive": True,
        "is_exploitable": is_exploitable,
        "exploitability_score": 0.5,
        "crash_type": "stack_overflow",
        "severity_assessment": "high",
        "cvss_score_estimate": 7.0,
        "attack_scenario": "scenario",
        "exploitation_primitives": ["overwrite"],
        "recommended_next_steps": "steps",
        "control_flow_hijack": True,
        "memory_write": True,
    }


class TestAnalyseCrashExploitabilityMapping:
    def test_abstained_verdict_maps_to_unknown(self, tmp_path):
        # A schema-nulled is_exploitable must not mint the definitive
        # "not_exploitable" string (pre-fix positive-ternary shape).
        ctx = _ctx(tmp_path)
        agent = _agent(tmp_path, _analysis(None))
        assert agent.analyse_crash(ctx) is True
        assert ctx.exploitability == "unknown"

    def test_explicit_false_maps_to_not_exploitable(self, tmp_path):
        ctx = _ctx(tmp_path)
        agent = _agent(tmp_path, _analysis(False))
        assert agent.analyse_crash(ctx) is True
        assert ctx.exploitability == "not_exploitable"

    def test_explicit_true_maps_to_exploitable(self, tmp_path):
        ctx = _ctx(tmp_path)
        agent = _agent(tmp_path, _analysis(True))
        assert agent.analyse_crash(ctx) is True
        assert ctx.exploitability == "exploitable"

    def test_unknown_still_skips_exploit_generation(self, tmp_path):
        # The abstention is honest AND conservative: no exploit
        # tokens are spent on a verdict the model never gave.
        ctx = _ctx(tmp_path)
        agent = _agent(tmp_path, _analysis(None))
        agent.analyse_crash(ctx)
        assert agent.generate_exploit(ctx) is False
