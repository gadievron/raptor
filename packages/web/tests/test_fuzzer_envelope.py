"""Tests that the web fuzzer's payload generation uses the defense envelope."""

from __future__ import annotations

from unittest.mock import MagicMock



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


class TestActiveTierPayloadContract:
    """Phase 6 authorises fuzzing at the ACTIVE tier (crafted probe
    values); payloads that destroy target state (DROP/TRUNCATE on a
    stacked-query-capable target) are intrusive-tier by the framework's
    own vocabulary and must not ship on any generation path."""

    def test_static_sqli_set_has_no_state_destroying_shapes(self):
        from packages.web.fuzzer import _DESTRUCTIVE_SQL_RE, WebFuzzer

        client = MagicMock()
        client.reveal_secrets = False
        fuzzer = WebFuzzer(client=client, llm=None)
        payloads = fuzzer._generate_payloads("id", "text", "sqli")
        assert payloads, "sqli class must keep non-mutating payloads"
        assert not any(_DESTRUCTIVE_SQL_RE.search(p) for p in payloads)
        # The error-oracle replacement detects the class via syntax
        # errors instead of mutation.
        assert "'" in payloads

    def test_llm_generated_destructive_sqli_is_dropped(self):
        from packages.web.fuzzer import WebFuzzer

        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = (
            {"payloads": [
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "1; TRUNCATE TABLE audit; --",
            ]},
            "raw",
        )
        client = MagicMock()
        client.reveal_secrets = False
        fuzzer = WebFuzzer(client=client, llm=mock_llm)
        payloads = fuzzer._generate_payloads("id", "text", "sqli")
        assert payloads == ["' OR 1=1--"]

    def test_extended_destructive_shapes_are_dropped(self):
        # EXEC/EXECUTE (procedure execution), REPLACE [INTO], MERGE,
        # and INTO OUTFILE/DUMPFILE (server-side file write) are
        # state-changing shapes too — in any casing, and with the
        # executable comment-between-keywords split.
        from packages.web.fuzzer import WebFuzzer

        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = (
            {"payloads": [
                "' OR 1=1--",
                "1; EXEC xp_cmdshell('dir')--",
                "1; execute immediate 'x'--",
                "'; REPLACE INTO users VALUES(1,'a')--",
                "1; MERGE INTO t USING d ON (1=1)--",
                "' UNION SELECT 1 INTO OUTFILE '/tmp/x'--",
                "' union select 1 into/**/dumpfile '/tmp/x'--",
            ]},
            "raw",
        )
        client = MagicMock()
        client.reveal_secrets = False
        fuzzer = WebFuzzer(client=client, llm=mock_llm)
        assert fuzzer._generate_payloads("id", "text", "sqli") == ["' OR 1=1--"]

    def test_error_based_sql_functions_survive_the_denylist(self):
        # updatexml/extractvalue are ERROR-based (non-mutating)
        # techniques; the word-bounded denylist must not eat them.
        from packages.web.fuzzer import WebFuzzer

        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = (
            {"payloads": [
                "' AND updatexml(1,concat(0x7e,version()),1)--",
                "' AND extractvalue(1,concat(0x7e,user()))--",
            ]},
            "raw",
        )
        client = MagicMock()
        client.reveal_secrets = False
        fuzzer = WebFuzzer(client=client, llm=mock_llm)
        payloads = fuzzer._generate_payloads("id", "text", "sqli")
        assert len(payloads) == 2

    def test_other_vuln_classes_pass_through_untouched(self):
        from packages.web.fuzzer import WebFuzzer

        client = MagicMock()
        client.reveal_secrets = False
        fuzzer = WebFuzzer(client=client, llm=None)
        assert fuzzer._generate_payloads("cmd", "text", "command_injection")


class TestPayloadBudget:
    def test_llm_reply_is_clamped_to_the_requested_count(self):
        from packages.web.fuzzer import WebFuzzer

        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = (
            {"payloads": [f"<x{i}>" for i in range(40)]},
            "raw",
        )
        client = MagicMock()
        client.reveal_secrets = False
        fuzzer = WebFuzzer(client=client, llm=mock_llm)
        # Each payload costs ~2 live requests per cell/class; the
        # request budget is the caller's count, not the model's mood.
        assert len(fuzzer._generate_payloads("q", "text", "xss")) == 10
