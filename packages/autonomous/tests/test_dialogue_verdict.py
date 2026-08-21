"""Verdict-parsing and refinement-contract tests for dialogue.py.

Covers:
- _parse_crash_analysis prefers an explicit verdict line over
  whole-response keyword co-occurrence (which parsed
  "Exploitability: LOW ... heap address is high" as high@0.8);
- keyword fallback checks conservative levels first with reduced
  confidence;
- the turn-2 confidence boost fires only when the clarification
  agrees with the initial verdict;
- refine_exploit_iteratively honors its "None if refinement failed"
  contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock

from packages.autonomous.dialogue import MultiTurnAnalyser


@dataclass
class FakeCrashContext:
    signal: int = 11
    function_name: Optional[str] = "vuln_func"
    stack_trace: str = "STACK_TRACE_MARKER_abc123"
    registers: str = "RAX=0xdeadbeef RBX=0x41414141"
    binary_info: dict = field(default_factory=lambda: {"aslr_enabled": True})
    size: int = 256


def _analyser(llm=None):
    return MultiTurnAnalyser(llm_client=llm or MagicMock())


def _mock_llm(responses):
    llm = MagicMock()
    replies = []
    for text in responses:
        r = MagicMock()
        r.content = text
        replies.append(r)
    llm.generate.side_effect = replies
    return llm


class TestParseCrashAnalysis:
    def test_explicit_low_wins_over_incidental_high(self):
        r = _analyser()._parse_crash_analysis(
            "Exploitability: LOW. The heap address is high in memory "
            "and any exploit would require a separate info leak.")
        assert r["exploitability"] == "low"
        assert r["confidence"] == 0.6

    def test_explicit_anchor_first(self):
        r = _analyser()._parse_crash_analysis(
            "Buffer overflow. Exploitability: High. Use ROP.")
        assert r["exploitability"] == "high"
        assert r["confidence"] == 0.8

    def test_level_before_anchor(self):
        r = _analyser()._parse_crash_analysis(
            "This crash has medium exploitability given ASLR.")
        assert r["exploitability"] == "medium"

    def test_not_exploitable(self):
        r = _analyser()._parse_crash_analysis(
            "Null deref in cleanup path; this is not exploitable.")
        assert r["exploitability"] == "none"

    def test_question_echo_does_not_match(self):
        # An echo of the prompt's option list must not be read as an
        # explicit verdict.
        r = _analyser()._parse_crash_analysis(
            "How exploitable is this? (High/Medium/Low/None) — "
            "I need more data.")
        assert r["confidence"] < 0.8

    def test_fallback_conservative_first_reduced_confidence(self):
        # No explicit verdict line: co-occurrence fallback must pick
        # low before high, at reduced confidence.
        r = _analyser()._parse_crash_analysis(
            "Chances of a working exploit are low; entropy is high.")
        assert r["exploitability"] == "low"
        assert r["confidence"] < 0.6

    def test_fallback_high_reduced_confidence(self):
        r = _analyser()._parse_crash_analysis(
            "An exploit is plausible; attacker control is high here.")
        assert r["exploitability"] == "high"
        assert r["confidence"] < 0.8

    def test_no_signal_stays_unknown(self):
        r = _analyser()._parse_crash_analysis("Crash in parser.")
        assert r["exploitability"] == "unknown"
        assert r["confidence"] == 0.5


class TestClarificationConfidenceBoost:
    def test_agreeing_clarification_boosts(self):
        llm = _mock_llm([
            "Exploitability: low. Stack overflow near return.",
            "Exploitability: low. Attacker controls neither location "
            "nor value.",
        ])
        result = _analyser(llm).analyse_crash_deeply(FakeCrashContext())
        assert result["exploitability"] == "low"
        assert result["confidence"] == 0.8  # 0.6 + 0.2

    def test_disagreeing_clarification_updates_without_boost(self):
        llm = _mock_llm([
            "Exploitability: low. Stack overflow near return.",
            "On reflection, exploitability: high — attacker controls "
            "the return address.",
        ])
        result = _analyser(llm).analyse_crash_deeply(FakeCrashContext())
        assert result["exploitability"] == "high"
        # Verdict flipped: no earned agreement, so no +0.2.
        assert result["confidence"] == 0.6

    def test_inconclusive_clarification_keeps_initial(self):
        llm = _mock_llm([
            "Exploitability: low. Stack overflow near return.",
            "I cannot tell without a debugger.",
        ])
        result = _analyser(llm).analyse_crash_deeply(FakeCrashContext())
        assert result["exploitability"] == "low"
        assert result["confidence"] == 0.6


class TestRefineExploitContract:
    def test_returns_none_when_no_code_extracted(self):
        llm = _mock_llm([
            "I cannot fix this exploit, sorry.",
            "Still cannot help.",
        ])
        analyser = _analyser(llm)
        result = analyser.refine_exploit_iteratively(
            "int main(void) { return 0; }",
            FakeCrashContext(),
            ["error: something"],
            max_iterations=2,
        )
        assert result is None

    def test_returns_code_on_successful_refinement(self):
        llm = _mock_llm([
            "```c\nint main(void) { return 0; }\n```",
        ])
        analyser = _analyser(llm)
        result = analyser.refine_exploit_iteratively(
            "broken",
            FakeCrashContext(),
            ["error: something"],
            max_iterations=1,
        )
        assert result == "int main(void) { return 0; }"

    def test_returns_none_when_refined_code_stays_invalid(self):
        # Extractable code that keeps failing the quick lexical check
        # is a failed refinement, not a result.
        bad = '```c\n#ifdef "__BROKEN\nint main(void){return 0;}\n```'
        llm = _mock_llm([bad, bad])
        analyser = _analyser(llm)
        result = analyser.refine_exploit_iteratively(
            "broken",
            FakeCrashContext(),
            ["error: something"],
            max_iterations=2,
        )
        assert result is None
