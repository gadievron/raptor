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
    # dict[str, str], matching the real CrashContext contract
    # (registers parsed from the debugger, not a pre-rendered string).
    registers: dict = field(default_factory=lambda: {
        "rax": "0xdeadbeef", "rbx": "0x41414141",
    })
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


class TestMemoryValidationBoost:
    """The turn-3 memory-validation confidence boost is earned only
    when memory AGREES with the verdict; a contradiction warning must
    never raise confidence."""

    @staticmethod
    def _run_with_memory(probability: float) -> dict:
        # Both turns say low -> turn-2 agreement lands confidence at
        # 0.8 (< 0.9), so the memory-validation turn runs.
        llm = _mock_llm([
            "Exploitability: low. Stack overflow near return.",
            "Exploitability: low. Attacker controls neither location "
            "nor value.",
        ])
        memory = MagicMock()
        memory.is_crash_likely_exploitable.return_value = probability
        analyser = MultiTurnAnalyser(llm_client=llm, memory=memory)
        return analyser.analyse_crash_deeply(FakeCrashContext(), max_turns=3)

    def test_consistent_memory_boosts_confidence(self):
        result = self._run_with_memory(0.5)  # consistent with "low"
        assert result["confidence"] == 0.9  # 0.8 + 0.1
        assert any(
            s["question"] == "Memory validation"
            for s in result["reasoning_steps"]
        )

    def test_contradicting_memory_does_not_boost(self):
        result = self._run_with_memory(0.9)  # contradicts "low"
        assert result["confidence"] == 0.8  # no boost
        # The warning is still recorded for the operator.
        steps = [
            s for s in result["reasoning_steps"]
            if s["question"] == "Memory validation"
        ]
        assert steps and "Warning" in steps[0]["response"]


class TestQuickValidateCode:
    """The lexical pre-check must not flag valid C: '\\T' occurs in
    Windows-path string literals and '\\0x' is a well-defined literal
    (octal \\0 escape followed by 'x')."""

    def test_windows_path_literal_passes(self):
        code = 'int main(void){ fopen("C:\\\\Temp\\\\x", "r"); return 0; }'
        assert _analyser()._quick_validate_code(code) == []

    def test_nul_then_x_shellcode_literal_passes(self):
        code = 'const char sc[] = "\\0x90\\0x90"; int main(void){return 0;}'
        assert _analyser()._quick_validate_code(code) == []

    def test_mangled_preprocessor_still_flagged(self):
        code = '#ifdef "__FOO\nint main(void){return 0;}'
        assert _analyser()._quick_validate_code(code)
