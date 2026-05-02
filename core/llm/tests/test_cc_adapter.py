"""Tests for core.llm.cc_adapter — CC subprocess transport utilities."""

import json

import pytest

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
