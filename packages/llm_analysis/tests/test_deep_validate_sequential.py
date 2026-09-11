"""--deep-validate / --no-deep-validate on the sequential path.

The orchestrated path threads these flags into the validation pass;
the sequential path (plain /analyze, no role flags) must honour them
too: the kill-switch disables the LLM-backed deep dataflow validation
(the free Tier 1 gate still runs), and force-enable widens the gate
to dataflow findings the analysis ruled non-exploitable.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.agent import (  # noqa: E402
    AutonomousSecurityAgentV2,
    VulnerabilityContext,
)


class _FakeLLM:
    """Minimal external-LLM stand-in for generate_structured."""

    def __init__(self, analysis: dict) -> None:
        self._analysis = analysis

    def generate_structured(self, **_kwargs):
        return dict(self._analysis), "raw response"


def _make_vuln(repo: Path, has_dataflow: bool = True) -> VulnerabilityContext:
    (repo / "vuln.c").write_text(
        "void f(char *s){char b[8];strcpy(b,s);}\n"
    )
    finding = {
        "finding_id": "F1",
        "rule_id": "cpp/unbounded-write",
        "file": "vuln.c",
        "startLine": 1,
        "endLine": 1,
        "message": "strcpy into fixed buffer",
        "level": "error",
        "has_dataflow": has_dataflow,
        "dataflow_path": {
            "source": {"file": "vuln.c", "line": 1, "label": "s"},
            "sink": {"file": "vuln.c", "line": 1, "label": "strcpy"},
            "steps": [],
            "total_steps": 2,
        } if has_dataflow else None,
    }
    return VulnerabilityContext(finding, repo)


def _agent(tmp_path: Path, *, exploitable: bool,
           deep_validate: bool = False,
           deep_validate_disabled: bool = False):
    analysis = {
        "is_true_positive": True,
        "is_exploitable": exploitable,
        "exploitability_score": 0.9 if exploitable else 0.1,
        "reasoning": "solid reasoning",
        "severity_assessment": "high",
        "confidence": "high",
    }
    calls: dict[str, int] = {"tier1": 0, "deep": 0}
    agent = SimpleNamespace(
        repo_path=tmp_path,
        out_dir=tmp_path / "out",
        llm=_FakeLLM(analysis),
        llm_config=None,
        use_verified_exemplars=False,
        deep_validate=deep_validate,
        deep_validate_disabled=deep_validate_disabled,
    )
    agent.out_dir.mkdir(exist_ok=True)
    agent._prompt_budget = lambda: 0
    agent._get_verified_outcomes = lambda: ()

    def _tier1(_vuln):
        calls["tier1"] += 1
        return "no_check"

    def _deep(_vuln):
        calls["deep"] += 1
        return {}

    agent._tier1_pre_flight = _tier1
    agent.validate_dataflow = _deep
    agent.analyze_vulnerability = (
        AutonomousSecurityAgentV2.analyze_vulnerability.__get__(
            agent, type(agent),
        )
    )
    return agent, calls


class TestSequentialDeepValidateGate:

    def test_default_exploitable_dataflow_runs_deep_validation(
        self, tmp_path,
    ):
        agent, calls = _agent(tmp_path, exploitable=True)
        assert agent.analyze_vulnerability(_make_vuln(tmp_path)) is True
        assert calls["tier1"] == 1
        assert calls["deep"] == 1

    def test_kill_switch_skips_llm_deep_validation(self, tmp_path):
        agent, calls = _agent(
            tmp_path, exploitable=True, deep_validate_disabled=True,
        )
        assert agent.analyze_vulnerability(_make_vuln(tmp_path)) is True
        # The free Tier 1 gate still ran; the LLM-backed step did not.
        assert calls["tier1"] == 1
        assert calls["deep"] == 0

    def test_force_enable_widens_to_non_exploitable(self, tmp_path):
        agent, calls = _agent(
            tmp_path, exploitable=False, deep_validate=True,
        )
        assert agent.analyze_vulnerability(_make_vuln(tmp_path)) is True
        assert calls["deep"] == 1

    def test_default_non_exploitable_skips_deep_validation(self, tmp_path):
        agent, calls = _agent(tmp_path, exploitable=False)
        assert agent.analyze_vulnerability(_make_vuln(tmp_path)) is True
        assert calls["deep"] == 0


class TestConstructorPlumbing:

    def test_flags_stored_on_agent(self, tmp_path):
        mock_availability = MagicMock()
        mock_availability.external_llm = False
        mock_availability.claude_code = True
        with patch(
            "packages.llm_analysis.agent.detect_llm_availability",
            return_value=mock_availability,
        ):
            agent = AutonomousSecurityAgentV2(
                repo_path=tmp_path,
                out_dir=tmp_path / "out",
                prep_only=True,
                deep_validate=True,
                deep_validate_disabled=True,
            )
        assert agent.deep_validate is True
        assert agent.deep_validate_disabled is True
