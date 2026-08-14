"""Tests for core.llm.cc_adapter — CC subprocess transport utilities."""

import json


from core.llm.cc_adapter import (
    CCDispatchConfig,
    build_cc_command,
    strip_json_fences,
    extract_envelope_metadata,
    parse_cc_structured,
    parse_cc_freeform,
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

    def test_handles_empty_lines(self):
        from core.llm.cc_adapter import parse_stream_json_lines
        r = parse_stream_json_lines(["", "  ", "not json"])
        assert r.content == ""
        assert r.session_id is None

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
