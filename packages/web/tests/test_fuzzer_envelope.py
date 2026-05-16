"""Tests that the web fuzzer's payload generation uses the defense envelope."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


class TestFuzzerEnvelope:

    def _make_fuzzer(self):
        from packages.web.fuzzer import WebFuzzer

        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = (
            {"payloads": ["' OR 1=1--"]},
            "raw",
        )
        mock_client = MagicMock()
        mock_client.reveal_secrets = False
        return WebFuzzer(client=mock_client, llm=mock_llm), mock_llm

    def test_generate_payloads_passes_system_prompt(self):
        fuzzer, mock_llm = self._make_fuzzer()
        fuzzer._generate_payloads("username", "text", "sqli")

        call_kwargs = mock_llm.generate_structured.call_args.kwargs
        assert "system_prompt" in call_kwargs
        assert call_kwargs["system_prompt"] is not None

    def test_param_name_in_user_not_system(self):
        fuzzer, mock_llm = self._make_fuzzer()
        fuzzer._generate_payloads("PARAM_NAME_MARKER_xyz", "text", "sqli")

        call_kwargs = mock_llm.generate_structured.call_args.kwargs
        assert "PARAM_NAME_MARKER_xyz" in call_kwargs["prompt"]
        assert "PARAM_NAME_MARKER_xyz" not in call_kwargs["system_prompt"]

    def test_param_name_marked_untrusted(self):
        fuzzer, mock_llm = self._make_fuzzer()
        fuzzer._generate_payloads("user_input", "text", "sqli")

        prompt = mock_llm.generate_structured.call_args.kwargs["prompt"]
        assert 'trust="untrusted"' in prompt
        assert "user_input" in prompt

    def test_vuln_type_marked_trusted(self):
        fuzzer, mock_llm = self._make_fuzzer()
        fuzzer._generate_payloads("q", "text", "sqli")

        prompt = mock_llm.generate_structured.call_args.kwargs["prompt"]
        assert 'trust="trusted"' in prompt

    def test_system_prompt_contains_priming(self):
        fuzzer, mock_llm = self._make_fuzzer()
        fuzzer._generate_payloads("q", "text", "sqli")

        system = mock_llm.generate_structured.call_args.kwargs["system_prompt"]
        assert "untrusted" in system.lower()
