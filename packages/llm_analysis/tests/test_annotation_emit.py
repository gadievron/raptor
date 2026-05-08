"""Tests for ``packages.llm_analysis.annotation_emit``.

Uses a hand-rolled stub vuln + checklist so the tests don't require
LLM, repository, or scanner state. The helper is pure substrate
glue, so unit-level isolation is appropriate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from packages.llm_analysis.annotation_emit import (
    _build_body,
    _derive_status,
    _resolve_function,
    _sanitise_meta,
    emit_finding_annotation,
)
from core.annotations import (
    Annotation,
    read_annotation,
    write_annotation,
)


# ---------------------------------------------------------------------------
# Stub vuln + checklist
# ---------------------------------------------------------------------------


@dataclass
class StubVuln:
    file_path: str = "src/auth.py"
    start_line: int = 12
    rule_id: str = "py/sql-injection"
    cwe_id: str = "CWE-89"
    tool: str = "codeql"
    message: str = "Tainted query string reaches cursor.execute"
    has_dataflow: bool = False
    analysis: Optional[Dict[str, Any]] = None


def _checklist_with_function(
    file_path="src/auth.py", name="login", line_start=10, line_end=25,
) -> Dict[str, Any]:
    return {
        "files": [
            {
                "path": file_path,
                "items": [
                    {
                        "name": name,
                        "line_start": line_start,
                        "line_end": line_end,
                    }
                ],
            }
        ]
    }


# ---------------------------------------------------------------------------
# _derive_status
# ---------------------------------------------------------------------------


class TestDeriveStatus:
    def test_false_positive_is_clean(self):
        assert _derive_status({"is_true_positive": False}) == "clean"

    def test_exploitable_true_is_finding(self):
        assert _derive_status({
            "is_true_positive": True, "is_exploitable": True,
        }) == "finding"

    def test_true_positive_not_exploitable_is_suspicious(self):
        assert _derive_status({
            "is_true_positive": True, "is_exploitable": False,
        }) == "suspicious"

    def test_missing_analysis_is_error(self):
        assert _derive_status(None) == "error"
        assert _derive_status({}) == "error"

    def test_missing_is_true_positive_is_error(self):
        assert _derive_status({"is_exploitable": True}) == "error"


# ---------------------------------------------------------------------------
# _resolve_function
# ---------------------------------------------------------------------------


class TestResolveFunction:
    def test_finds_function_by_line(self, tmp_path):
        ck = _checklist_with_function()
        v = StubVuln(file_path="src/auth.py", start_line=12)
        result = _resolve_function(v, ck, tmp_path)
        assert result == ("login", 10, 25)

    def test_returns_none_no_checklist(self, tmp_path):
        v = StubVuln()
        assert _resolve_function(v, None, tmp_path) is None
        assert _resolve_function(v, {}, tmp_path) is None

    def test_returns_none_no_file_path(self, tmp_path):
        ck = _checklist_with_function()
        v = StubVuln(file_path="", start_line=12)
        assert _resolve_function(v, ck, tmp_path) is None

    def test_returns_none_no_line(self, tmp_path):
        ck = _checklist_with_function()
        v = StubVuln(start_line=0)
        assert _resolve_function(v, ck, tmp_path) is None

    def test_returns_none_no_match(self, tmp_path):
        ck = _checklist_with_function(file_path="src/other.py")
        v = StubVuln(file_path="src/auth.py")
        assert _resolve_function(v, ck, tmp_path) is None

    def test_returns_none_when_function_lacks_name(self, tmp_path):
        ck = {
            "files": [
                {
                    "path": "src/auth.py",
                    "items": [{"line_start": 10, "line_end": 25}],
                },
            ],
        }
        v = StubVuln()
        assert _resolve_function(v, ck, tmp_path) is None


# ---------------------------------------------------------------------------
# _build_body
# ---------------------------------------------------------------------------


class TestBuildBody:
    def test_uses_reasoning_field(self):
        v = StubVuln(analysis={"reasoning": "Tainted from request.args"})
        body = _build_body(v)
        assert "Tainted from request.args" in body

    def test_includes_severity(self):
        v = StubVuln(analysis={
            "reasoning": "x", "severity_assessment": "high",
        })
        body = _build_body(v)
        assert "Severity: high" in body

    def test_falls_back_to_scanner_message(self):
        v = StubVuln(analysis=None)
        body = _build_body(v)
        assert "Scanner message" in body
        assert "Tainted query string" in body

    def test_dataflow_validation_appended(self):
        v = StubVuln(
            has_dataflow=True,
            analysis={
                "reasoning": "x",
                "dataflow_validation": {"false_positive": False},
            },
        )
        body = _build_body(v)
        assert "false_positive=False" in body


# ---------------------------------------------------------------------------
# _sanitise_meta
# ---------------------------------------------------------------------------


class TestSanitiseMeta:
    def test_strips_newlines(self):
        assert "\n" not in _sanitise_meta("line1\nline2")

    def test_strips_html_comment_close(self):
        assert "-->" not in _sanitise_meta("evil-->payload")

    def test_strips_html_comment_open(self):
        assert "<!--" not in _sanitise_meta("evil<!--payload")

    def test_preserves_normal_text(self):
        assert _sanitise_meta("CWE-78") == "CWE-78"


# ---------------------------------------------------------------------------
# emit_finding_annotation
# ---------------------------------------------------------------------------


class TestEmitFindingAnnotation:
    def test_writes_annotation_for_finding(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "src").mkdir()
        (repo / "src" / "auth.py").write_text(
            "\n" * 9 + "def login(req):\n    return query(req)\n" * 8
        )
        ann_base = tmp_path / "anns"
        ck = _checklist_with_function()
        v = StubVuln(analysis={
            "is_true_positive": True,
            "is_exploitable": True,
            "reasoning": "Tainted from request.args reaches cursor.execute",
            "exploitability_score": 0.85,
            "severity_assessment": "high",
        })
        path = emit_finding_annotation(
            v, base_dir=ann_base, checklist=ck, repo_root=repo,
        )
        assert path is not None
        ann = read_annotation(ann_base, "src/auth.py", "login")
        assert ann is not None
        assert ann.metadata["status"] == "finding"
        assert ann.metadata["source"] == "llm"
        assert ann.metadata["cwe"] == "CWE-89"
        assert ann.metadata["rule_id"] == "py/sql-injection"
        assert ann.metadata["score"] == "0.85"
        assert ann.metadata.get("hash"), "hash should be stamped"
        assert "Tainted from request.args" in ann.body

    def test_returns_none_no_checklist(self, tmp_path):
        v = StubVuln(analysis={"is_true_positive": False})
        result = emit_finding_annotation(
            v, base_dir=tmp_path, checklist=None, repo_root=tmp_path,
        )
        assert result is None

    def test_returns_none_function_not_in_inventory(self, tmp_path):
        # Checklist exists but doesn't cover the finding's file.
        ck = _checklist_with_function(file_path="src/other.py")
        v = StubVuln(file_path="src/auth.py")
        result = emit_finding_annotation(
            v, base_dir=tmp_path, checklist=ck, repo_root=tmp_path,
        )
        assert result is None

    def test_status_clean_for_false_positive(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        ann_base = tmp_path / "anns"
        ck = _checklist_with_function()
        v = StubVuln(analysis={
            "is_true_positive": False,
            "reasoning": "Operator already validates this input upstream",
        })
        emit_finding_annotation(
            v, base_dir=ann_base, checklist=ck, repo_root=repo,
        )
        ann = read_annotation(ann_base, "src/auth.py", "login")
        assert ann.metadata["status"] == "clean"

    def test_status_suspicious_for_true_positive_not_exploitable(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        ann_base = tmp_path / "anns"
        ck = _checklist_with_function()
        v = StubVuln(analysis={
            "is_true_positive": True,
            "is_exploitable": False,
            "reasoning": "Real bug but no reachable attacker path",
        })
        emit_finding_annotation(
            v, base_dir=ann_base, checklist=ck, repo_root=repo,
        )
        ann = read_annotation(ann_base, "src/auth.py", "login")
        assert ann.metadata["status"] == "suspicious"

    def test_respects_manual_annotation(self, tmp_path):
        """Operator manual note must not be clobbered by /agentic."""
        repo = tmp_path / "repo"
        repo.mkdir()
        ann_base = tmp_path / "anns"
        # Operator wrote a manual note first.
        write_annotation(ann_base, Annotation(
            file="src/auth.py", function="login",
            body="reviewer: Alice — clean after manual review",
            metadata={"source": "human", "status": "clean"},
        ))
        # /agentic comes along.
        ck = _checklist_with_function()
        v = StubVuln(analysis={
            "is_true_positive": True, "is_exploitable": True,
            "reasoning": "LLM disagrees",
        })
        result = emit_finding_annotation(
            v, base_dir=ann_base, checklist=ck, repo_root=repo,
        )
        assert result is None  # respect-manual blocked the write
        # Manual content intact.
        ann = read_annotation(ann_base, "src/auth.py", "login")
        assert ann.metadata["source"] == "human"
        assert "Alice" in ann.body

    def test_skip_when_no_line_bounds_in_inventory(self, tmp_path):
        """If the inventory entry has no line_end, hash is skipped but
        annotation should still be written (with name only)."""
        repo = tmp_path / "repo"
        repo.mkdir()
        ann_base = tmp_path / "anns"
        ck = {
            "files": [{
                "path": "src/auth.py",
                "items": [{
                    "name": "login", "line_start": 10,
                    # no line_end
                }],
            }],
        }
        v = StubVuln(analysis={
            "is_true_positive": True, "is_exploitable": False,
            "reasoning": "...",
        })
        path = emit_finding_annotation(
            v, base_dir=ann_base, checklist=ck, repo_root=repo,
        )
        assert path is not None
        ann = read_annotation(ann_base, "src/auth.py", "login")
        assert "hash" not in ann.metadata

    def test_swallows_unexpected_errors(self, tmp_path, monkeypatch):
        """Any exception inside emit must be logged and swallowed —
        annotation failures cannot break /agentic."""
        ck = _checklist_with_function()
        v = StubVuln(analysis={"is_true_positive": False})

        # Force write_annotation to blow up.
        from packages.llm_analysis import annotation_emit as mod

        def boom(*args, **kwargs):
            raise RuntimeError("simulated disk failure")

        monkeypatch.setattr(mod, "write_annotation", boom)
        # Should not raise.
        result = emit_finding_annotation(
            v, base_dir=tmp_path, checklist=ck, repo_root=tmp_path,
        )
        assert result is None
