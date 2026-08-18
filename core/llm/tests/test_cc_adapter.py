"""Tests for core.llm.cc_adapter — CC subprocess transport utilities."""

import json

from core.llm.cc_adapter import (
    CCDispatchConfig,
    build_cc_command,
    extract_envelope_metadata,
    parse_cc_freeform,
    parse_cc_structured,
    strip_json_fences,
)


class TestBuildCCCommand:
    def test_minimal_config(self):
        config = CCDispatchConfig(claude_bin="/usr/bin/claude")
        cmd = build_cc_command(config)
        assert cmd[0] == "/usr/bin/claude"
        assert "-p" in cmd
        assert "--no-session-persistence" in cmd
        assert cmd[cmd.index("--allowed-tools") + 1] == "Read,Grep,Glob"
        assert cmd[cmd.index("--max-budget-usd") + 1] == "1.00"
        assert "--output-format" in cmd
        # gh #549: strict_mcp defaults to True so sub-agents don't
        # inherit the operator's ~/.claude.json MCP servers.
        assert "--strict-mcp-config" in cmd
        # Value must include the `mcpServers` key (even empty);
        # bare `{}` is rejected by recent Claude Code MCP validation
        # (`mcpServers: Invalid input: expected record, received
        # undefined`).
        assert cmd[cmd.index("--mcp-config") + 1] == '{"mcpServers": {}}'

    def test_strict_mcp_can_be_disabled(self):
        # Opt-out path for any future consumer that genuinely needs MCP.
        config = CCDispatchConfig(claude_bin="claude", strict_mcp=False)
        cmd = build_cc_command(config)
        assert "--strict-mcp-config" not in cmd
        assert "--mcp-config" not in cmd

    def test_no_envelope(self):
        config = CCDispatchConfig(claude_bin="claude", capture_json_envelope=False)
        cmd = build_cc_command(config)
        assert "--output-format" not in cmd

    def test_add_dirs(self):
        config = CCDispatchConfig(claude_bin="claude", add_dirs=("/a", "/b"))
        cmd = build_cc_command(config)
        indices = [i for i, v in enumerate(cmd) if v == "--add-dir"]
        assert len(indices) == 2
        assert cmd[indices[0] + 1] == "/a"
        assert cmd[indices[1] + 1] == "/b"

    def test_json_schema(self):
        schema = {"type": "object", "properties": {"x": {"type": "string"}}}
        config = CCDispatchConfig(claude_bin="claude", json_schema=schema)
        cmd = build_cc_command(config)
        idx = cmd.index("--json-schema")
        assert json.loads(cmd[idx + 1]) == schema


class TestStripJsonFences:
    def test_no_fences(self):
        assert strip_json_fences('{"a": 1}') == '{"a": 1}'

    def test_json_fence(self):
        text = "Here:\n```json\n{\"a\": 1}\n```\n"
        assert strip_json_fences(text) == '{"a": 1}'

    def test_plain_fence(self):
        text = "```\n{\"a\": 1}\n```"
        assert strip_json_fences(text) == '{"a": 1}'

    def test_no_json_inside(self):
        text = "```\nsome text\n```"
        assert strip_json_fences(text) == text

    def test_single_line_fence_with_language_tag(self):
        # ``_structured_fallback``/Gemini route through this helper
        # now — the inline copies they replaced handled a one-line
        # fenced block with the tag on the same line.
        text = '```json {"a": 1}```'
        assert strip_json_fences(text) == '{"a": 1}'

    def test_multiline_array_own_bracket_line(self):
        # A fenced array's leading ``[`` alone on the first line must
        # not be treated as a language tag.
        text = "prose\n```\n[\n1,\n2\n]\n```\nmore prose"
        assert strip_json_fences(text) == "[\n1,\n2\n]"

    def test_language_tagged_object_still_stripped(self):
        text = "```json\n{\"a\": 1}\n```"
        assert strip_json_fences(text) == '{"a": 1}'


class TestParseCCStructured:
    def test_valid_json(self):
        result = parse_cc_structured(
            json.dumps({"finding_id": "f-001", "is_exploitable": True}),
            "", "f-001",
        )
        assert result["finding_id"] == "f-001"
        assert "error" not in result

    def test_markdown_fenced_json(self):
        content = "Here is the result:\n```json\n" + json.dumps({
            "finding_id": "f-001", "is_exploitable": False, "reasoning": "test"
        }) + "\n```\n"
        result = parse_cc_structured(content, "", "f-001")
        assert result["finding_id"] == "f-001"
        assert "error" not in result

    def test_empty_output(self):
        result = parse_cc_structured("", "some error", "f-001")
        assert result["finding_id"] == "f-001"
        assert "error" in result

    def test_invalid_json(self):
        result = parse_cc_structured("This is not JSON at all", "", "f-001")
        assert "error" in result

    def test_json_embedded_in_text(self):
        content = 'I found that {"finding_id": "f-001", "is_exploitable": true, "reasoning": "vuln"} is the result.'
        result = parse_cc_structured(content, "", "f-001")
        assert result["finding_id"] == "f-001"
        assert "error" not in result

    def test_multiple_json_fragments_takes_first(self):
        content = 'prefix {"partial": true} and {"finding_id": "f-001", "is_exploitable": false, "reasoning": "safe"} end'
        result = parse_cc_structured(content, "", "f-001")
        assert "error" not in result

    def test_claude_output_format_json_envelope(self):
        envelope = json.dumps({
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": "",
            "session_id": "abc-123",
            "total_cost_usd": 0.15,
            "structured_output": {
                "finding_id": "f-001",
                "is_true_positive": True,
                "is_exploitable": True,
                "exploitability_score": 0.9,
                "reasoning": "Stack buffer overflow",
            }
        })
        result = parse_cc_structured(envelope, "", "f-001")
        assert result["finding_id"] == "f-001"
        assert result["is_exploitable"] is True
        assert result["exploitability_score"] == 0.9
        assert result["reasoning"] == "Stack buffer overflow"
        assert "session_id" not in result


class TestParseCCStructuredEnvelopeError:
    """is_error envelopes are errors, not findings.

    ``parse_cc_structured`` must honour the envelope's in-band failure
    signal (``is_error`` / non-empty ``error``) instead of returning a
    failed run's envelope as a valid parsed finding.
    """

    def test_is_error_envelope_without_structured_output_is_error(self):
        envelope = (
            '{"type": "result", "is_error": true, "result": "",'
            ' "total_cost_usd": 0.12, "duration_ms": 3400}'
        )
        parsed = parse_cc_structured(envelope, "", "f-1")
        assert parsed["finding_id"] == "f-1"
        assert "error" in parsed
        assert "is_error" in parsed["error"]
        # Failed runs still cost money — telemetry survives.
        assert parsed["cost_usd"] == 0.12
        assert parsed["duration_seconds"] == 3.4

    def test_error_field_envelope_is_error(self):
        envelope = '{"type": "result", "error": "budget exceeded"}'
        parsed = parse_cc_structured(envelope, "", "f-2")
        assert parsed["error"] == "budget exceeded"
        assert parsed["finding_id"] == "f-2"

    def test_string_true_is_error_flag_counts(self):
        envelope = '{"is_error": "true", "result": ""}'
        parsed = parse_cc_structured(envelope, "", "f-3")
        assert "error" in parsed

    def test_semantically_empty_error_strings_are_not_errors(self):
        # "false"/"none"/"null"/"0"/"" are truthy-string noise, not
        # failures — same semantics as parse_cc_freeform. The dict is
        # returned verbatim (keeping its own keys), NOT collapsed into
        # an error-only result that would drop the payload fields.
        for noise in ("false", "none", "null", "0", ""):
            envelope = f'{{"error": "{noise}", "verdict": "ok"}}'
            parsed = parse_cc_structured(envelope, "", "f-4")
            assert parsed["verdict"] == "ok", noise
            assert parsed.get("error") == noise, noise

    def test_structured_output_still_wins(self):
        # A validated structured_output object is the success path;
        # its presence keeps the pre-existing behaviour.
        envelope = (
            '{"type": "result", "is_error": false,'
            ' "structured_output": {"verdict": "exploitable"}}'
        )
        parsed = parse_cc_structured(envelope, "", "f-5")
        assert parsed["verdict"] == "exploitable"
        assert "error" not in parsed

    def test_envelope_error_text_is_defanged_and_redacted(self):
        secret = "sk-" + "a" * 48
        envelope_error = f"boom \x1b[31m {secret}"
        envelope = json.dumps({"is_error": True, "error": envelope_error})
        parsed = parse_cc_structured(envelope, "", "f-6")
        assert secret not in parsed["error"]
        assert "\x1b" not in parsed["error"]
        assert "[REDACTED]" in parsed["error"]

    def test_plain_structured_dict_unchanged(self):
        # A non-envelope dict (no is_error / error fields) is returned
        # verbatim with the transport-injected finding_id.
        parsed = parse_cc_structured('{"verdict": "ok"}', "", "f-7")
        assert parsed == {"verdict": "ok", "finding_id": "f-7"}


class TestParseCCFreeform:
    def test_extracts_content_and_cost(self):
        envelope = json.dumps({
            "type": "result",
            "result": "Here is the exploit code:\n```python\nimport os\n```",
            "total_cost_usd": 0.18,
            "duration_ms": 12500,
            "modelUsage": {"claude-sonnet-4-20250514": {}},
            "usage": {"input_tokens": 1000, "output_tokens": 500},
        })
        parsed = parse_cc_freeform(envelope, "")
        assert "exploit code" in parsed["content"]
        assert parsed["cost_usd"] == 0.18
        assert parsed["duration_seconds"] == 12.5
        assert parsed["analysed_by"] == "claude-sonnet-4-20250514"
        assert parsed["_tokens"] == 1500

    def test_empty_output(self):
        parsed = parse_cc_freeform("", "some error")
        assert "error" in parsed

    def test_non_json_fallback(self):
        parsed = parse_cc_freeform("Just plain text output", "")
        assert parsed["content"] == "Just plain text output"

    def test_envelope_without_cost(self):
        envelope = json.dumps({"type": "result", "result": "analysis text"})
        parsed = parse_cc_freeform(envelope, "")
        assert parsed["content"] == "analysis text"
        assert "cost_usd" not in parsed

    # Error-signal semantics stay symmetric with parse_cc_structured —
    # pin both directions.

    def test_is_error_still_flagged(self):
        parsed = parse_cc_freeform('{"result": "", "is_error": true}')
        assert parsed["error"] == "claude -p reported is_error=true"

    def test_error_false_still_clean(self):
        parsed = parse_cc_freeform('{"result": "hi", "error": "false"}')
        assert "error" not in parsed
        assert parsed["content"] == "hi"


class TestExtractEnvelopeMetadata:
    def test_full_envelope(self):
        envelope = {
            "total_cost_usd": 0.25,
            "duration_ms": 5000,
            "modelUsage": {"claude-opus-4-20250514": {}},
            "usage": {"input_tokens": 200, "output_tokens": 100},
        }
        into: dict = {}
        extract_envelope_metadata(envelope, into)
        assert into["cost_usd"] == 0.25
        assert into["duration_seconds"] == 5.0
        assert into["analysed_by"] == "claude-opus-4-20250514"
        assert into["_tokens"] == 300

    def test_empty_envelope(self):
        into: dict = {}
        extract_envelope_metadata({}, into)
        assert "cost_usd" not in into
        assert into["analysed_by"] == "claude-code"

    def test_string_usage_does_not_crash(self):
        # A non-dict ``usage`` field degrades instead of crashing.
        into: dict = {}
        extract_envelope_metadata({"usage": "corrupt"}, into)
        assert "_tokens" not in into

    def test_dict_usage_still_counted(self):
        into: dict = {}
        extract_envelope_metadata(
            {"usage": {"input_tokens": 3, "output_tokens": 4}}, into,
        )
        assert into["_tokens"] == 7


class TestBuildCCCommandResume:
    def test_persist_session_omits_no_session_persistence(self):
        config = CCDispatchConfig(
            claude_bin="claude", persist_session=True,
        )
        cmd = build_cc_command(config)
        assert "--no-session-persistence" not in cmd

    def test_session_id_adds_resume_flag(self):
        config = CCDispatchConfig(
            claude_bin="claude",
            session_id="abc-123",
            persist_session=True,
        )
        cmd = build_cc_command(config)
        idx = cmd.index("--resume")
        assert cmd[idx + 1] == "abc-123"
        assert "--no-session-persistence" not in cmd

    def test_default_has_no_session_persistence(self):
        config = CCDispatchConfig(claude_bin="claude")
        cmd = build_cc_command(config)
        assert "--no-session-persistence" in cmd
        assert "--resume" not in cmd


class TestExtractSessionId:
    def test_extracts_from_envelope(self):
        from core.llm.cc_adapter import extract_session_id
        stdout = json.dumps({
            "result": "4",
            "session_id": "eefdf10d-f8a1-490b-88f2-219f7c26a9d8",
            "total_cost_usd": 0.01,
        })
        assert extract_session_id(stdout) == "eefdf10d-f8a1-490b-88f2-219f7c26a9d8"

    def test_returns_none_for_missing_field(self):
        from core.llm.cc_adapter import extract_session_id
        assert extract_session_id(json.dumps({"result": "ok"})) is None

    def test_returns_none_for_invalid_json(self):
        from core.llm.cc_adapter import extract_session_id
        assert extract_session_id("not json") is None

    def test_returns_none_for_empty(self):
        from core.llm.cc_adapter import extract_session_id
        assert extract_session_id("") is None


class TestBuildCCCommandStreamJson:
    def test_stream_json_sets_output_format(self):
        config = CCDispatchConfig(
            claude_bin="claude", stream_json=True,
            capture_json_envelope=True,
        )
        cmd = build_cc_command(config)
        idx = cmd.index("--output-format")
        assert cmd[idx + 1] == "stream-json"
        assert "--verbose" in cmd

    def test_stream_json_overrides_json_envelope(self):
        config = CCDispatchConfig(
            claude_bin="claude", stream_json=True,
            capture_json_envelope=True,
        )
        cmd = build_cc_command(config)
        assert cmd.count("--output-format") == 1
        assert cmd[cmd.index("--output-format") + 1] == "stream-json"


class TestParseStreamJsonLines:
    def test_parses_assistant_and_result(self):
        from core.llm.cc_adapter import parse_stream_json_lines
        lines = [
            json.dumps({
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "hello"}],
                    "model": "claude-haiku-4-5-20251001",
                    "usage": {
                        "input_tokens": 100,
                        "output_tokens": 50,
                        "cache_read_input_tokens": 80,
                    },
                },
            }),
            json.dumps({
                "type": "result",
                "session_id": "sess-abc",
                "total_cost_usd": 0.005,
                "is_error": False,
            }),
        ]
        r = parse_stream_json_lines(lines)
        assert r.content == "hello"
        assert r.session_id == "sess-abc"
        assert r.cost_usd == 0.005
        assert r.input_tokens == 100
        assert r.output_tokens == 50
        assert r.cache_read_tokens == 80
        assert r.model == "claude-haiku-4-5-20251001"
        assert r.error is None

    def test_multiple_assistant_messages_accumulate(self):
        """CC stream-json can emit several ``assistant`` lines per
        invocation (one per message). Earlier text must not be
        silently dropped, and usage must be summed — the previous
        overwrite kept only the last message's text and counters."""
        from core.llm.cc_adapter import parse_stream_json_lines

        def assistant(text, in_tok, out_tok, cache_read=0):
            return json.dumps({
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": text}],
                    "model": "claude-haiku-4-5-20251001",
                    "usage": {
                        "input_tokens": in_tok,
                        "output_tokens": out_tok,
                        "cache_read_input_tokens": cache_read,
                    },
                },
            })

        r = parse_stream_json_lines([
            assistant("first part", 100, 40, cache_read=80),
            assistant("second part", 5, 60, cache_read=20),
        ])
        assert r.content == "first part\nsecond part"
        assert r.input_tokens == 100 + 5
        assert r.output_tokens == 40 + 60
        assert r.cache_read_tokens == 80 + 20

    def test_result_event_overrides_accumulated_usage(self):
        """The final ``result`` event's usage stays authoritative
        where present."""
        from core.llm.cc_adapter import parse_stream_json_lines
        lines = [
            json.dumps({
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "hi"}],
                    "usage": {"input_tokens": 1, "output_tokens": 2},
                },
            }),
            json.dumps({
                "type": "result",
                "session_id": "sess-1",
                "usage": {"input_tokens": 111, "output_tokens": 222},
                "is_error": False,
            }),
        ]
        r = parse_stream_json_lines(lines)
        assert r.input_tokens == 111
        assert r.output_tokens == 222

    def test_ignores_system_lines(self):
        from core.llm.cc_adapter import parse_stream_json_lines
        lines = [
            json.dumps({"type": "system", "subtype": "hook_started"}),
            json.dumps({
                "type": "assistant",
                "message": {
                    "content": [{"type": "text", "text": "hi"}],
                    "usage": {},
                },
            }),
            json.dumps({"type": "result", "session_id": "s1"}),
        ]
        r = parse_stream_json_lines(lines)
        assert r.content == "hi"
        assert r.session_id == "s1"

    def test_handles_error_result(self):
        from core.llm.cc_adapter import parse_stream_json_lines
        lines = [
            json.dumps({
                "type": "result",
                "is_error": True,
                "result": "something broke",
            }),
        ]
        r = parse_stream_json_lines(lines)
        assert r.error == "something broke"

    def test_error_result_empty_text_falls_back_to_subtype(self):
        # Budget-cap aborts emit is_error with result "" and the cause
        # only in subtype (error_max_budget_usd).
        from core.llm.cc_adapter import parse_stream_json_lines
        lines = [
            json.dumps({
                "type": "result",
                "is_error": True,
                "subtype": "error_max_budget_usd",
                "result": "",
            }),
        ]
        r = parse_stream_json_lines(lines)
        assert r.error == "error_max_budget_usd"

    def test_handles_empty_lines(self):
        from core.llm.cc_adapter import parse_stream_json_lines
        r = parse_stream_json_lines(["", "  ", "not json"])
        assert r.content == ""
        assert r.session_id is None

    def test_structured_output_captured_from_result(self):
        # CLI >= 2.1.x delivers --json-schema output via a
        # StructuredOutput tool call: assistant messages carry no text
        # blocks, the object arrives on the result event.
        from core.llm.cc_adapter import parse_stream_json_lines
        lines = [
            json.dumps({
                "type": "assistant",
                "message": {
                    "content": [{
                        "type": "tool_use",
                        "name": "StructuredOutput",
                        "input": {"answer": "42"},
                    }],
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                },
            }),
            json.dumps({
                "type": "result",
                "session_id": "s2",
                "structured_output": {"answer": "42"},
                "result": '{"answer": "42"}',
            }),
        ]
        r = parse_stream_json_lines(lines)
        assert r.structured_output == {"answer": "42"}
        assert r.content == ""
        assert r.error is None

    def test_structured_output_non_dict_ignored(self):
        from core.llm.cc_adapter import parse_stream_json_lines
        lines = [
            json.dumps({"type": "result", "structured_output": "oops"}),
        ]
        r = parse_stream_json_lines(lines)
        assert r.structured_output is None

    def test_result_usage_overrides_assistant_usage(self):
        from core.llm.cc_adapter import parse_stream_json_lines
        lines = [
            json.dumps({
                "type": "assistant",
                "message": {
                    "content": [{"type": "text", "text": "x"}],
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                },
            }),
            json.dumps({
                "type": "result",
                "usage": {"input_tokens": 100, "output_tokens": 50},
            }),
        ]
        r = parse_stream_json_lines(lines)
        assert r.input_tokens == 100
        assert r.output_tokens == 50


class TestCcSubprocessEnv:
    """cc_subprocess_env: safe baseline + backend overlay."""

    def test_backend_families_overlaid(self, monkeypatch):
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("ANTHROPIC_MODEL", "anthropic.claude-mythos-5")
        monkeypatch.setenv("AWS_PROFILE", "mythos")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        env = cc_subprocess_env()
        assert env["CLAUDE_CODE_USE_BEDROCK"] == "1"
        assert env["ANTHROPIC_MODEL"] == "anthropic.claude-mythos-5"
        assert env["AWS_PROFILE"] == "mythos"
        assert env["AWS_REGION"] == "us-east-1"

    def test_aws_gated_on_bedrock(self, monkeypatch):
        """AWS credentials must not reach CLI children on installs
        that never selected Bedrock — some children run with tools
        enabled against hostile repos."""
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
        monkeypatch.setenv("AWS_PROFILE", "prod")
        env = cc_subprocess_env()
        assert "AWS_ACCESS_KEY_ID" not in env
        assert "AWS_PROFILE" not in env

    def test_dangerous_vars_still_stripped(self, monkeypatch):
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.setenv("BASH_ENV", "/tmp/evil")
        monkeypatch.setenv("PYTHONSTARTUP", "/tmp/evil.py")
        env = cc_subprocess_env()
        assert "BASH_ENV" not in env
        assert "PYTHONSTARTUP" not in env

    def test_safe_baseline_preserved(self, monkeypatch):
        from core.llm.cc_adapter import cc_subprocess_env
        env = cc_subprocess_env()
        assert "PATH" in env
        assert "HOME" in env

    def test_operator_proxy_propagated(self, monkeypatch):
        """Mandatory-egress-proxy hosts: the CLI child has no route to
        any backend unless the operator's proxy env survives."""
        from core.llm import egress
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.setattr(egress, "_original_proxy_env", None)
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp:3128")
        monkeypatch.setenv("NO_PROXY", "169.254.169.254")
        env = cc_subprocess_env()
        assert env["HTTPS_PROXY"] == "http://proxy.corp:3128"
        assert env["NO_PROXY"] == "169.254.169.254"

    def test_proxy_snapshot_wins_over_egress_rewrite(self, monkeypatch):
        """After enable_llm_egress points HTTPS_PROXY at the in-process
        loopback proxy, children must still get the operator's original
        route — the loopback proxy's allowlist doesn't cover the CLI's
        backend hosts."""
        from core.llm import egress
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:45123")
        monkeypatch.setattr(
            egress, "_original_proxy_env",
            {"HTTPS_PROXY": "http://proxy.corp:3128"},
        )
        env = cc_subprocess_env()
        assert env["HTTPS_PROXY"] == "http://proxy.corp:3128"


class TestCcSubprocessEnvProxyMode:
    """credential_mode="proxy": the child holds ZERO provider
    credentials — only the minted dispatcher token and loopback base
    URL. The env-construction invariant the credential-proxy posture
    rests on."""

    _BASE = "http://127.0.0.1:61781"   # dispatcher gateway origin
    _TOKEN = "minted-child-token-value"

    def _proxy_env(self):
        from core.llm.cc_adapter import cc_subprocess_env
        return cc_subprocess_env(
            credential_mode="proxy",
            proxy_base_url=self._BASE,
            proxy_auth_token=self._TOKEN,
        )

    def test_zero_credential_material(self, monkeypatch):
        """Grep the whole env dict for credential-family names — only
        the minted token may be present."""
        import re
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-SECRET")
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "operator-gateway-token")
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "SECRETKEY")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "SESSTOKEN")
        monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "BRTOKEN")
        monkeypatch.setenv("AWS_PROFILE", "prod")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        env = self._proxy_env()
        cred_shaped = re.compile(r"AWS_|API_KEY|SECRET|BEARER")
        offenders = [k for k in env if cred_shaped.search(k)]
        assert offenders == []
        # And no credential VALUE leaked under another name.
        joined = json.dumps(env)
        for secret in ("sk-ant-SECRET", "AKIAEXAMPLE", "SECRETKEY",
                       "SESSTOKEN", "BRTOKEN", "operator-gateway-token"):
            assert secret not in joined
        # The one credential present is the minted scoped token,
        # riding the Bedrock gateway route family (USE_BEDROCK install).
        assert env["ANTHROPIC_AUTH_TOKEN"] == self._TOKEN
        assert env["ANTHROPIC_BEDROCK_MANTLE_BASE_URL"] == (
            self._BASE + "/bedrock/mantle"
        )
        assert env["ANTHROPIC_BEDROCK_BASE_URL"] == self._BASE + "/bedrock"
        assert "ANTHROPIC_BASE_URL" not in env

    def test_bedrock_gateway_route_family(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.delenv("CLAUDE_CODE_USE_MANTLE", raising=False)
        # Operator pins must not survive — the dispatcher gateway is
        # the child's one and only backend.
        monkeypatch.setenv("ANTHROPIC_BEDROCK_BASE_URL", "https://gw.example")
        monkeypatch.setenv("CLAUDE_CODE_SKIP_AWS_CRED_CACHE", "1")
        monkeypatch.setenv("RAPTOR_CC_EFFORT", "high")
        monkeypatch.setenv("RAPTOR_BEDROCK_MODEL", "anthropic.claude-x")
        env = self._proxy_env()
        # Backend-selection flags KEPT (the CLI's provider mode decides
        # which gateway vars it reads); Mantle surface forced.
        assert env["CLAUDE_CODE_USE_BEDROCK"] == "1"
        assert env["CLAUDE_CODE_USE_MANTLE"] == "1"
        # Gateway routes are OURS, not the operator pin.
        assert env["ANTHROPIC_BEDROCK_BASE_URL"] == self._BASE + "/bedrock"
        assert env["ANTHROPIC_BEDROCK_MANTLE_BASE_URL"] == (
            self._BASE + "/bedrock/mantle"
        )
        # Skip-auth flags reset to exactly what this mode needs.
        assert env["CLAUDE_CODE_SKIP_MANTLE_AUTH"] == "1"
        assert env["CLAUDE_CODE_SKIP_BEDROCK_AUTH"] == "1"
        assert "CLAUDE_CODE_SKIP_AWS_CRED_CACHE" not in env
        # Non-credential knobs still ride the overlay.
        assert env["RAPTOR_CC_EFFORT"] == "high"
        assert env["RAPTOR_BEDROCK_MODEL"] == "anthropic.claude-x"

    def test_api_install_routes_via_anthropic(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_USE_MANTLE", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_USE_VERTEX", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_USE_FOUNDRY", raising=False)
        env = self._proxy_env()
        assert env["ANTHROPIC_BASE_URL"] == self._BASE + "/anthropic"
        assert "ANTHROPIC_BEDROCK_MANTLE_BASE_URL" not in env

    def test_vertex_install_rejected(self, monkeypatch):
        import pytest
        monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
        monkeypatch.setenv("CLAUDE_CODE_USE_VERTEX", "1")
        with pytest.raises(ValueError, match="Vertex"):
            self._proxy_env()

    def test_bedrock_model_pins_normalized_to_mantle(self, monkeypatch):
        from core.llm.bedrock_prefixes import mantle_model_id
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv(
            "ANTHROPIC_MODEL", "us.anthropic.claude-opus-4-8",
        )
        env = self._proxy_env()
        assert env["ANTHROPIC_MODEL"] == mantle_model_id(
            "us.anthropic.claude-opus-4-8",
        )

    def test_no_proxy_gains_loopback_and_keeps_operator_entries(
        self, monkeypatch,
    ):
        """Mandatory-proxy hosts break when the corporate proxy
        hijacks loopback traffic — the child must reach the
        dispatcher's 127.0.0.1 base URL DIRECT."""
        from core.llm import egress
        monkeypatch.setattr(egress, "_original_proxy_env", None)
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
        monkeypatch.setenv("NO_PROXY", "internal.example")
        env = self._proxy_env()
        entries = [p.strip() for p in env["NO_PROXY"].split(",")]
        assert "internal.example" in entries   # operator entry preserved
        assert "127.0.0.1" in entries
        assert "localhost" in entries
        assert env["no_proxy"] == env["NO_PROXY"]
        # Operator proxy still available for anything non-loopback.
        assert env["HTTPS_PROXY"] == "http://proxy.example:3128"

    def test_proxy_mode_requires_route_and_token(self):
        import pytest

        from core.llm.cc_adapter import cc_subprocess_env
        with pytest.raises(ValueError, match="fail fast"):
            cc_subprocess_env(credential_mode="proxy")
        with pytest.raises(ValueError, match="fail fast"):
            cc_subprocess_env(
                credential_mode="proxy", proxy_base_url=self._BASE,
            )

    def test_invalid_mode_and_misused_args_rejected(self):
        import pytest

        from core.llm.cc_adapter import cc_subprocess_env
        with pytest.raises(ValueError, match="credential_mode"):
            cc_subprocess_env(credential_mode="direct")
        with pytest.raises(ValueError, match="only valid"):
            cc_subprocess_env(proxy_auth_token="tok")

    def test_no_aws_minting_in_proxy_mode(self, monkeypatch):
        """Proxy mode must never call the AWS credential chain — even
        on a Bedrock install where env mode would mint."""
        import core.llm.cc_adapter as cc_adapter
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")

        def _boom(env):
            raise AssertionError("_mint_child_aws_credentials called")

        monkeypatch.setattr(
            cc_adapter, "_mint_child_aws_credentials", _boom,
        )
        env = self._proxy_env()
        assert "AWS_ACCESS_KEY_ID" not in env


class TestNeutralCwd:
    def test_creates_private_dir_once(self):
        import os

        from core.llm.cc_adapter import neutral_cwd
        d1 = neutral_cwd()
        d2 = neutral_cwd()
        assert d1 == d2
        assert os.path.isdir(d1)
        assert os.path.basename(d1).startswith("raptor-cc-cwd-")
        # mkdtemp guarantees 0700 — no other local user can plant
        # .claude hooks the CLI child would execute.
        assert (os.stat(d1).st_mode & 0o777) == 0o700
        assert os.listdir(d1) == []


class TestResolveClaudeCli:
    """resolve_claude_cli: realpath at the dispatch resolution seam.

    Symlinked installs (~/.local/bin/claude -> versioned dir) failed
    the mount-ns visibility check when cmd[0] was the un-realpath'd
    which() result — silent isolation downgrade to Landlock-only.
    """

    def test_none_when_not_found(self, monkeypatch):
        from core.llm.cc_adapter import resolve_claude_cli
        monkeypatch.setattr("shutil.which", lambda _: None)
        assert resolve_claude_cli() is None

    def test_path_lookup_result_is_realpathed(self, monkeypatch, tmp_path):
        from core.llm.cc_adapter import resolve_claude_cli
        real = tmp_path / "versions" / "2.1" / "claude"
        real.parent.mkdir(parents=True)
        real.write_text("#!/bin/sh\n")
        link = tmp_path / "bin" / "claude"
        link.parent.mkdir()
        link.symlink_to(real)
        monkeypatch.setattr("shutil.which", lambda _: str(link))
        assert resolve_claude_cli() == str(real.resolve())

    def test_explicit_path_is_realpathed(self, tmp_path):
        from core.llm.cc_adapter import resolve_claude_cli
        real = tmp_path / "install" / "claude"
        real.parent.mkdir()
        real.write_text("#!/bin/sh\n")
        link = tmp_path / "claude"
        link.symlink_to(real)
        assert resolve_claude_cli(str(link)) == str(real.resolve())

    def test_regular_path_unchanged(self, tmp_path):
        from core.llm.cc_adapter import resolve_claude_cli
        p = tmp_path / "claude"
        p.write_text("#!/bin/sh\n")
        assert resolve_claude_cli(str(p)) == str(p.resolve())


class TestMintChildAwsCredentials:
    """S4 validate post-pass root cause: sandboxed CLI children cannot
    resolve IAM-role credentials themselves (Landlock denies ~/.aws,
    egress denies IMDS) — the parent must resolve its chain and attach
    frozen session credentials at its own trust boundary."""

    def _frozen(self, token="tok"):
        from unittest.mock import MagicMock
        frozen = MagicMock()
        frozen.access_key = "ASIAMINTED"
        frozen.secret_key = "secret-minted"
        frozen.token = token
        return frozen

    def _install_botocore_stub(self, monkeypatch, session_cls):
        """Install a stub ``botocore.session`` module in sys.modules.

        The code under test is RAPTOR's minting logic, not botocore —
        stubbing the module (rather than monkeypatching the real one)
        keeps these tests running on bare CI where botocore, an
        optional parent-only dependency, is not installed
        (test_bedrock_detection precedent). On provisioned hosts the
        stub shadows the real module for the test's duration only.
        """
        import sys
        import types
        pkg = types.ModuleType("botocore")
        mod = types.ModuleType("botocore.session")
        mod.Session = session_cls
        pkg.session = mod
        monkeypatch.setitem(sys.modules, "botocore", pkg)
        monkeypatch.setitem(sys.modules, "botocore.session", mod)

    def _patch_session(self, monkeypatch, frozen):
        from unittest.mock import MagicMock
        creds = MagicMock()
        creds.get_frozen_credentials.return_value = frozen
        session = MagicMock()
        session.get_credentials.return_value = creds
        session_cls = MagicMock(return_value=session)
        self._install_botocore_stub(monkeypatch, session_cls)
        return session_cls

    def test_mints_when_no_secret_material(self, monkeypatch):
        from core.llm.cc_adapter import _mint_child_aws_credentials
        session_cls = self._patch_session(monkeypatch, self._frozen())
        env = {"AWS_PROFILE": "mythos", "AWS_REGION": "us-east-1",
               "AWS_CONFIG_FILE": "/home/op/.aws/config"}
        _mint_child_aws_credentials(env)
        assert env["AWS_ACCESS_KEY_ID"] == "ASIAMINTED"
        assert env["AWS_SECRET_ACCESS_KEY"] == "secret-minted"
        assert env["AWS_SESSION_TOKEN"] == "tok"
        # Profile/config pointers dropped: the SDK default chain skips
        # env credentials when AWS_PROFILE is set, and the profile is
        # unreadable inside the sandbox anyway. Region pin survives.
        assert "AWS_PROFILE" not in env
        assert "AWS_CONFIG_FILE" not in env
        assert env["AWS_REGION"] == "us-east-1"
        # The parent's profile drove the resolution.
        assert session_cls.call_args.kwargs["profile"] == "mythos"

    def test_static_key_present_no_mint(self, monkeypatch):
        from core.llm.cc_adapter import _mint_child_aws_credentials
        session_cls = self._patch_session(monkeypatch, self._frozen())
        env = {"AWS_ACCESS_KEY_ID": "AKIASTATIC", "AWS_PROFILE": "p"}
        _mint_child_aws_credentials(env)
        session_cls.assert_not_called()
        assert env["AWS_ACCESS_KEY_ID"] == "AKIASTATIC"
        assert env["AWS_PROFILE"] == "p"

    def test_bearer_token_present_no_mint(self, monkeypatch):
        from core.llm.cc_adapter import _mint_child_aws_credentials
        session_cls = self._patch_session(monkeypatch, self._frozen())
        env = {"AWS_BEARER_TOKEN_BEDROCK": "bearer"}
        _mint_child_aws_credentials(env)
        session_cls.assert_not_called()

    def test_resolution_failure_is_loud_and_nonfatal(
        self, monkeypatch, caplog,
    ):
        from core.llm.cc_adapter import _mint_child_aws_credentials

        def boom(**kwargs):
            raise RuntimeError("no chain")
        self._install_botocore_stub(monkeypatch, boom)
        env = {"AWS_PROFILE": "mythos"}
        with caplog.at_level("WARNING", logger="core.llm.cc_adapter"):
            _mint_child_aws_credentials(env)  # must not raise
        assert "AWS_ACCESS_KEY_ID" not in env
        assert any("credential" in r.getMessage().lower()
                   for r in caplog.records)

    def test_empty_chain_is_loud_and_nonfatal(self, monkeypatch, caplog):
        from unittest.mock import MagicMock

        from core.llm.cc_adapter import _mint_child_aws_credentials
        session = MagicMock()
        session.get_credentials.return_value = None
        self._install_botocore_stub(
            monkeypatch, MagicMock(return_value=session),
        )
        env = {}
        with caplog.at_level("WARNING", logger="core.llm.cc_adapter"):
            _mint_child_aws_credentials(env)
        assert "AWS_ACCESS_KEY_ID" not in env
        assert any("Could not load credentials" in r.getMessage()
                   for r in caplog.records)

    def test_cc_subprocess_env_minting_is_opt_in(self, monkeypatch):
        """Default calls never touch the credential chain — only
        sandboxed dispatch sites opt in."""
        from unittest.mock import MagicMock

        from core.llm.cc_adapter import cc_subprocess_env
        session_cls = MagicMock()
        self._install_botocore_stub(monkeypatch, session_cls)
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("AWS_PROFILE", "mythos")
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        env = cc_subprocess_env()
        session_cls.assert_not_called()
        assert env["AWS_PROFILE"] == "mythos"

    def test_cc_subprocess_env_mints_when_opted_in(self, monkeypatch):
        from core.llm.cc_adapter import cc_subprocess_env
        self._patch_session(monkeypatch, self._frozen())
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("AWS_PROFILE", "mythos")
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
        env = cc_subprocess_env(mint_aws_credentials=True)
        assert env["AWS_ACCESS_KEY_ID"] == "ASIAMINTED"
        assert env["AWS_SESSION_TOKEN"] == "tok"
        assert "AWS_PROFILE" not in env

    def test_non_bedrock_never_mints(self, monkeypatch):
        from unittest.mock import MagicMock

        from core.llm.cc_adapter import cc_subprocess_env
        session_cls = MagicMock()
        self._install_botocore_stub(monkeypatch, session_cls)
        monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
        cc_subprocess_env(mint_aws_credentials=True)
        session_cls.assert_not_called()

    def test_botocore_absent_is_loud_and_nonfatal(self, monkeypatch, caplog):
        """Degradation contract for botocore-less installs: no mint,
        no raise, a warning that names the missing piece. Simulated by
        forcing the import to fail regardless of the host install."""
        import sys

        from core.llm.cc_adapter import _mint_child_aws_credentials
        monkeypatch.setitem(sys.modules, "botocore", None)
        monkeypatch.setitem(sys.modules, "botocore.session", None)
        env = {"AWS_PROFILE": "mythos"}
        with caplog.at_level("WARNING", logger="core.llm.cc_adapter"):
            _mint_child_aws_credentials(env)  # must not raise
        assert "AWS_ACCESS_KEY_ID" not in env
        assert any("botocore" in r.getMessage() for r in caplog.records)


class TestCcEnvCredentialScoping:
    """Regression: the Bedrock gate used to copy the entire ambient
    AWS_* prefix — static long-lived secrets included — plus the
    first-party ANTHROPIC_API_KEY into CLI children that run with
    Bash+Write against hostile repos. Secret material is now scoped:
    named non-secret AWS vars pass through, the session trio comes
    from the mint (sandboxed children) or the explicit static
    passthrough (unsandboxed substrate children), and the Anthropic
    key survives only where the child's provider requires it."""

    def _install_mint_stub(self, monkeypatch):
        import sys
        import types
        from unittest.mock import MagicMock
        frozen = MagicMock()
        frozen.access_key = "ASIAMINTED"
        frozen.secret_key = "secret-minted"
        frozen.token = "tok"
        creds = MagicMock()
        creds.get_frozen_credentials.return_value = frozen
        session = MagicMock()
        session.get_credentials.return_value = creds
        pkg = types.ModuleType("botocore")
        mod = types.ModuleType("botocore.session")
        mod.Session = MagicMock(return_value=session)
        pkg.session = mod
        monkeypatch.setitem(sys.modules, "botocore", pkg)
        monkeypatch.setitem(sys.modules, "botocore.session", mod)

    def test_bedrock_no_blanket_aws_prefix_copy(self, monkeypatch):
        from core.llm.cc_adapter import cc_subprocess_env
        self._install_mint_stub(monkeypatch)
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIASTATICLONGLIVED")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "static-secret")
        monkeypatch.setenv("AWS_UNRELATED_TOOL_SECRET", "leakme")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        env = cc_subprocess_env(mint_aws_credentials=True)
        # Ambient static secret is never copied verbatim into the
        # sandboxed child; the minted session values replace it.
        assert env["AWS_ACCESS_KEY_ID"] == "ASIAMINTED"
        assert env["AWS_SECRET_ACCESS_KEY"] == "secret-minted"
        assert env["AWS_SESSION_TOKEN"] == "tok"
        # Arbitrary ambient AWS_* names no longer ride the prefix.
        assert "AWS_UNRELATED_TOOL_SECRET" not in env
        # Named non-secret selection vars still pass.
        assert env["AWS_REGION"] == "us-east-1"

    def test_bedrock_drops_first_party_anthropic_secrets(self, monkeypatch):
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "tok")
        monkeypatch.setenv("ANTHROPIC_MODEL", "example.model-mapping-id")
        env = cc_subprocess_env()
        assert "ANTHROPIC_API_KEY" not in env
        assert "ANTHROPIC_AUTH_TOKEN" not in env
        # Non-secret model mapping still flows.
        assert env["ANTHROPIC_MODEL"] == "example.model-mapping-id"

    def test_vertex_drops_first_party_anthropic_secrets(self, monkeypatch):
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
        monkeypatch.setenv("CLAUDE_CODE_USE_VERTEX", "1")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        env = cc_subprocess_env()
        assert "ANTHROPIC_API_KEY" not in env

    def test_first_party_keeps_anthropic_key(self, monkeypatch):
        """On first-party API installs the key IS the child's auth."""
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_USE_VERTEX", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        env = cc_subprocess_env()
        assert env["ANTHROPIC_API_KEY"] == "sk-ant-xxx"

    def test_unsandboxed_substrate_static_trio_passthrough(self, monkeypatch):
        """mint=False (pure-LLM substrate) children cannot re-resolve
        env-provided static credentials — exactly that named trio
        passes; arbitrary AWS_* still does not."""
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIASTATIC")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "static-secret")
        monkeypatch.setenv("AWS_UNRELATED_TOOL_SECRET", "leakme")
        env = cc_subprocess_env()
        assert env["AWS_ACCESS_KEY_ID"] == "AKIASTATIC"
        assert env["AWS_SECRET_ACCESS_KEY"] == "static-secret"
        assert "AWS_UNRELATED_TOOL_SECRET" not in env

    def test_bearer_token_passthrough_on_bedrock(self, monkeypatch):
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bearer-tok")
        env = cc_subprocess_env()
        assert env["AWS_BEARER_TOKEN_BEDROCK"] == "bearer-tok"

    def test_non_bedrock_gets_no_aws_names(self, monkeypatch):
        from core.llm.cc_adapter import cc_subprocess_env
        monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
        monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bearer-tok")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        env = cc_subprocess_env()
        assert "AWS_BEARER_TOKEN_BEDROCK" not in env
        assert "AWS_REGION" not in env
