"""Tests for core.analysis.lifecycle_audit_integration — orchestrator wiring."""

from __future__ import annotations

import json
from pathlib import Path

from core.analysis.lifecycle_audit_integration import (
    check_lifecycle_at_function,
    format_lifecycle_evidence,
    lifecycle_findings_to_constraints,
)
from core.analysis.lifecycle_model import (
    LifecycleFinding,
    ReadSite,
    StateField,
)


def _setup_context_map(tmp_path: Path) -> None:
    """Write a context-map with the ptrace dumpability field."""
    cm = {
        "state_fields": [
            {
                "name": "dumpable",
                "struct_type": "task_struct",
                "invariant": "meaningful only when task owns an mm",
                "cwe": "CWE-863",
                "write_sites": [
                    {
                        "file": "fs/exec.c",
                        "line": 100,
                        "function": "setup_new_exec",
                        "guards": [
                            {"condition": "current->mm", "file": "fs/exec.c", "line": 95},
                        ],
                    },
                ],
                "read_sites": [
                    {
                        "file": "kernel/ptrace.c",
                        "line": 200,
                        "function": "__ptrace_may_access",
                        "guards": [],
                    },
                ],
            },
        ],
    }
    (tmp_path / "context-map.json").write_text(json.dumps(cm))


class TestCheckLifecycleAtFunction:
    def test_finds_violation(self, tmp_path):
        _setup_context_map(tmp_path)
        findings = check_lifecycle_at_function(
            file_path="kernel/ptrace.c",
            function_name="__ptrace_may_access",
            source="int x = get_dumpable(task);",
            out_dir=tmp_path,
        )
        assert len(findings) == 1
        assert "current->mm" in findings[0].missing_guards

    def test_no_state_fields(self, tmp_path):
        findings = check_lifecycle_at_function(
            file_path="kernel/ptrace.c",
            function_name="__ptrace_may_access",
            source="",
            out_dir=tmp_path,
        )
        assert findings == []

    def test_irrelevant_function(self, tmp_path):
        _setup_context_map(tmp_path)
        findings = check_lifecycle_at_function(
            file_path="kernel/ptrace.c",
            function_name="some_other_function",
            source="",
            out_dir=tmp_path,
        )
        assert findings == []


class TestFormatEvidence:
    def test_empty(self):
        assert format_lifecycle_evidence([]) == ""

    def test_formats_finding(self):
        field = StateField(
            name="dumpable", struct_type="task_struct",
            invariant="requires mm", cwe="CWE-863",
        )
        rs = ReadSite(
            file="ptrace.c", line=200, function="check_access",
            guards=frozenset(),
        )
        finding = LifecycleFinding(
            state_field=field, read_site=rs,
            missing_guards=frozenset({"current->mm"}),
            confidence="high",
        )
        text = format_lifecycle_evidence([finding])
        assert "task_struct.dumpable" in text
        assert "current->mm" in text
        assert "high" in text


class TestToConstraints:
    def test_converts_to_precondition(self):
        field = StateField(
            name="dumpable", struct_type="task_struct",
            invariant="requires mm", cwe="CWE-863",
        )
        rs = ReadSite(
            file="ptrace.c", line=200, function="check_access",
            guards=frozenset(),
        )
        finding = LifecycleFinding(
            state_field=field, read_site=rs,
            missing_guards=frozenset({"current->mm"}),
        )
        constraints = lifecycle_findings_to_constraints([finding])
        assert len(constraints) == 1
        c = constraints[0]
        assert c["kind"] == "precondition"
        assert c["target"] == "task_struct.dumpable"
        assert c["cwe"] == "CWE-863"
        assert c["function"] == "check_access"
        assert c["propagation"] == "callers"
