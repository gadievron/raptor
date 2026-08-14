"""Tests for core.audit.findings — findings emission."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.findings import (
    emit_finding,
    load_findings,
    write_findings,
)


class TestEmitFinding:
    def test_basic_finding(self, tmp_path: Path):
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="src/handler.c",
            function_name="parse_request",
            line=42,
            title="Buffer overflow in parse_request",
            description="Unbounded memcpy with user-controlled length.",
            cwe="CWE-120",
            severity="high",
            tool_evidence=[
                {"tool": "semgrep", "rule": "unbounded-memcpy", "output": "match at line 42"},
            ],
            hypothesis="If user-supplied length exceeds buffer size, memcpy overflows.",
        )

        assert finding["file"] == "src/handler.c"
        assert finding["cwe"] == "CWE-120"
        assert finding["origin"] == "audit"
        assert len(finding["tool_evidence"]) == 1

        findings = load_findings(tmp_path)
        assert len(findings) == 1

    def test_finding_without_cwe(self, tmp_path: Path):
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="src/splice.c",
            function_name="do_splice",
            line=100,
            title="Page cache aliasing",
            description="Read-only pages aliased into writable buffer.",
        )

        assert finding["vuln_type"] == "novel"
        assert "cwe" not in finding

    def test_multiple_findings_appended(self, tmp_path: Path):
        emit_finding(
            out_dir=tmp_path,
            file_path="a.c",
            function_name="f1",
            line=10,
            title="First",
            description="First finding.",
        )
        emit_finding(
            out_dir=tmp_path,
            file_path="b.c",
            function_name="f2",
            line=20,
            title="Second",
            description="Second finding.",
        )

        findings = load_findings(tmp_path)
        assert len(findings) == 2
        assert findings[0]["title"] == "First"
        assert findings[1]["title"] == "Second"


class TestLoadFindings:
    def test_load_list_format(self, tmp_path: Path):
        (tmp_path / "findings.json").write_text(json.dumps([
            {"title": "A", "file": "a.c"},
        ]))
        findings = load_findings(tmp_path)
        assert len(findings) == 1

    def test_load_dict_format(self, tmp_path: Path):
        (tmp_path / "findings.json").write_text(json.dumps({
            "findings": [
                {"title": "A", "file": "a.c"},
            ],
        }))
        findings = load_findings(tmp_path)
        assert len(findings) == 1

    def test_load_missing(self, tmp_path: Path):
        findings = load_findings(tmp_path)
        assert findings == []


class TestWriteFindings:
    def test_writes_json(self, tmp_path: Path):
        findings = [{"title": "Test", "file": "a.c", "line": 1}]
        path = write_findings(findings, tmp_path)
        assert path.exists()

        with open(path) as f:
            data = json.load(f)
        assert len(data) == 1
