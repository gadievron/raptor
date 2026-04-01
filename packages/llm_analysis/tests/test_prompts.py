"""Tests for shared prompt builders."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.llm_analysis.prompts import (
    build_analysis_prompt,
    build_analysis_prompt_from_finding,
    build_analysis_schema,
    build_exploit_prompt,
    build_exploit_prompt_from_finding,
    build_patch_prompt,
    build_patch_prompt_from_finding,
    ANALYSIS_SYSTEM_PROMPT,
    EXPLOIT_SYSTEM_PROMPT,
    PATCH_SYSTEM_PROMPT,
    ANALYSIS_SCHEMA,
    DATAFLOW_SCHEMA_FIELDS,
    FINDING_RESULT_SCHEMA,
)


class TestAnalysisPrompt:
    def test_includes_finding_metadata(self):
        prompt = build_analysis_prompt(
            rule_id="py/sql-injection", level="error",
            file_path="db.py", start_line=42, end_line=45,
            message="SQL injection", code="cursor.execute(f'...')",
        )
        assert "py/sql-injection" in prompt
        assert "db.py" in prompt
        assert "42" in prompt

    def test_includes_code_when_no_dataflow(self):
        prompt = build_analysis_prompt(
            rule_id="sqli", level="error", file_path="db.py",
            start_line=42, end_line=42, message="",
            code="cursor.execute(query)",
        )
        assert "cursor.execute(query)" in prompt

    def test_includes_dataflow_when_available(self):
        prompt = build_analysis_prompt(
            rule_id="sqli", level="error", file_path="db.py",
            start_line=42, end_line=42, message="",
            has_dataflow=True,
            dataflow_source={"file": "routes.py", "line": 15, "label": "HTTP param", "code": "req.args"},
            dataflow_sink={"file": "db.py", "line": 42, "label": "SQL query", "code": "cursor.execute()"},
            dataflow_steps=[{"file": "utils.py", "line": 20, "label": "transform", "is_sanitizer": False, "code": "x = y"}],
        )
        assert "routes.py:15" in prompt
        assert "db.py:42" in prompt
        assert "DATAFLOW" in prompt

    def test_includes_validation_methodology(self):
        prompt = build_analysis_prompt(
            rule_id="sqli", level="error", file_path="db.py",
            start_line=42, end_line=42, message="SQL injection",
            code="cursor.execute(query)",
        )
        assert "Stage A" in prompt
        assert "Stage B" in prompt
        assert "Stage C" in prompt
        assert "Stage D" in prompt
        assert "ruling" in prompt.lower()

    def test_from_finding_dict(self):
        finding = {
            "rule_id": "sqli", "level": "error", "file_path": "db.py",
            "start_line": 42, "end_line": 42, "message": "injection",
            "code": "bad code", "surrounding_context": "context",
        }
        prompt = build_analysis_prompt_from_finding(finding)
        assert "sqli" in prompt
        assert "bad code" in prompt


class TestAnalysisSchema:
    def test_base_schema(self):
        schema = build_analysis_schema()
        assert "is_exploitable" in schema
        assert "dataflow_exploitable" not in schema

    def test_schema_with_dataflow(self):
        schema = build_analysis_schema(has_dataflow=True)
        assert "is_exploitable" in schema
        assert "dataflow_exploitable" in schema


class TestExploitPrompt:
    def test_includes_analysis(self):
        prompt = build_exploit_prompt(
            rule_id="sqli", file_path="db.py", start_line=42, level="error",
            analysis={"is_exploitable": True, "reasoning": "injectable"},
            code="bad()", surrounding_context="ctx",
        )
        assert "injectable" in prompt
        assert "Mark Dowd" in prompt

    def test_includes_feasibility_constraints(self):
        prompt = build_exploit_prompt(
            rule_id="bof", file_path="vuln.c", start_line=10, level="error",
            analysis={}, code="strcpy(buf, input)",
            feasibility={"chain_breaks": ["Full RELRO"], "what_would_help": ["Format string"]},
        )
        assert "Full RELRO" in prompt
        assert "Format string" in prompt


class TestPatchPrompt:
    def test_includes_analysis(self):
        prompt = build_patch_prompt(
            rule_id="sqli", file_path="db.py", start_line=42, end_line=42,
            message="injection", analysis={"reasoning": "use parameterised"},
            code="bad()", full_file_content="full file",
        )
        assert "use parameterised" in prompt
        assert "SECURE PATCH" in prompt


class TestSystemPrompts:
    def test_system_prompts_not_empty(self):
        assert len(ANALYSIS_SYSTEM_PROMPT) > 50
        assert len(EXPLOIT_SYSTEM_PROMPT) > 50
        assert len(PATCH_SYSTEM_PROMPT) > 50


class TestFindingResultSchema:
    def test_is_valid_json_schema(self):
        assert FINDING_RESULT_SCHEMA["type"] == "object"
        assert "finding_id" in FINDING_RESULT_SCHEMA["required"]

    def test_has_ruling_field(self):
        assert "ruling" in FINDING_RESULT_SCHEMA["properties"]
        # ruling should be nullable string, not strict enum
        # (enum is guidance in the prompt, not enforcement in schema)
        ruling_type = FINDING_RESULT_SCHEMA["properties"]["ruling"]["type"]
        assert "string" in ruling_type

    def test_has_validation_fields(self):
        props = FINDING_RESULT_SCHEMA["properties"]
        assert "is_true_positive" in props
        assert "is_exploitable" in props
        assert "reasoning" in props
