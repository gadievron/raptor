"""Tests for core.audit.validate — /validate-compatible findings emission."""

from __future__ import annotations

import json

import pytest
from pathlib import Path

from core.audit.orchestrator import OrchestratorResult, ReviewOutcome
from core.audit.validate import (
    _build_audit_validate_prompt,
    _copy_findings_for_validate,
    _dispatch_validate,
    _emit_findings_json,
    _extract_cwe,
    _resolve_vuln_type,
    validate_findings,
)


def _result(*outcomes):
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    r.findings = sum(1 for o in outcomes if o.status == "finding")
    r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
    r.clean = sum(1 for o in outcomes if o.status == "clean")
    r.reviewed = len(outcomes)
    return r


def _outcome(file="a.c", function="foo", status="finding", body="bug",
             hypothesis="", review_result=None, line=0):
    return ReviewOutcome(
        file=file, function=function, status=status, body=body,
        hypothesis=hypothesis, review_result=review_result, line=line,
    )


class TestEmitFindings:
    def test_emits_container_format(self, tmp_path):
        outcomes = [
            (0, _outcome(body="buffer overflow", hypothesis="off-by-one")),
            (1, _outcome(file="b.c", function="bar", body="sql injection")),
        ]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        data = json.loads((tmp_path / "findings.json").read_text())
        assert isinstance(data, dict)
        assert data["stage"] == "audit"
        assert data["source"] == "audit"
        assert data["target_path"] == "/target"
        assert len(data["findings"]) == 2

    def test_finding_has_required_fields(self, tmp_path):
        outcomes = [
            (0, _outcome(
                body="overflow",
                review_result={"cwe": "CWE-120"},
                line=42,
            )),
        ]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        finding = json.loads((tmp_path / "findings.json").read_text())["findings"][0]
        assert finding["id"] == "FIND-001"
        assert finding["file"] == "a.c"
        assert finding["function"] == "foo"
        assert finding["line"] == 42
        assert finding["vuln_type"] == "buffer_overflow"
        assert finding["status"] == "pending"
        assert finding["origin"] == "pre_existing"
        assert finding["cwe_id"] == "CWE-120"

    def test_line_defaults_to_1_when_zero(self, tmp_path):
        outcomes = [(0, _outcome(line=0))]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        finding = json.loads((tmp_path / "findings.json").read_text())["findings"][0]
        assert finding["line"] == 1

    def test_line_from_outcome(self, tmp_path):
        outcomes = [(0, _outcome(line=275))]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        finding = json.loads((tmp_path / "findings.json").read_text())["findings"][0]
        assert finding["line"] == 275

    def test_sequential_ids(self, tmp_path):
        outcomes = [
            (0, _outcome()),
            (1, _outcome(file="b.c", function="bar")),
            (2, _outcome(file="c.c", function="baz")),
        ]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        findings = json.loads((tmp_path / "findings.json").read_text())["findings"]
        assert [f["id"] for f in findings] == ["FIND-001", "FIND-002", "FIND-003"]

    def test_empty_list(self, tmp_path):
        _emit_findings_json([], tmp_path, Path("/target"))
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data["findings"] == []

    def test_unknown_cwe_maps_to_other(self, tmp_path):
        outcomes = [
            (0, _outcome(review_result={"cwe": "CWE-999"})),
        ]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        finding = json.loads((tmp_path / "findings.json").read_text())["findings"][0]
        assert finding["vuln_type"] == "other"

    def test_no_cwe_maps_to_other(self, tmp_path):
        outcomes = [(0, _outcome())]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        finding = json.loads((tmp_path / "findings.json").read_text())["findings"][0]
        assert finding["vuln_type"] == "other"
        assert "cwe_id" not in finding

    def test_vuln_type_from_review_result(self, tmp_path):
        outcomes = [
            (0, _outcome(review_result={"vuln_type": "sql_injection", "cwe": "CWE-89"})),
        ]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        finding = json.loads((tmp_path / "findings.json").read_text())["findings"][0]
        assert finding["vuln_type"] == "sql_injection"

    def test_vuln_type_alias_normalised(self, tmp_path):
        outcomes = [
            (0, _outcome(review_result={"vuln_type": "sqli"})),
        ]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        finding = json.loads((tmp_path / "findings.json").read_text())["findings"][0]
        assert finding["vuln_type"] == "sql_injection"

    def test_vuln_type_from_review_result_takes_precedence(self, tmp_path):
        outcomes = [
            (0, _outcome(review_result={
                "vuln_type": "path_traversal",
                "cwe": "CWE-120",
            })),
        ]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        finding = json.loads((tmp_path / "findings.json").read_text())["findings"][0]
        assert finding["vuln_type"] == "path_traversal"


class TestResolveVulnType:
    def test_from_cwe(self):
        o = _outcome(review_result={"cwe": "CWE-78"})
        assert _resolve_vuln_type(o, "CWE-78") == "command_injection"

    def test_from_review_result(self):
        o = _outcome(review_result={"vuln_type": "xss"})
        assert _resolve_vuln_type(o, "") == "xss"

    def test_review_result_takes_precedence(self):
        o = _outcome(review_result={"vuln_type": "path_traversal", "cwe": "CWE-120"})
        assert _resolve_vuln_type(o, "CWE-120") == "path_traversal"

    def test_alias_normalised(self):
        o = _outcome(review_result={"vuln_type": "toctou"})
        assert _resolve_vuln_type(o, "") == "race_condition"

    def test_cwe_case_insensitive(self):
        o = _outcome()
        assert _resolve_vuln_type(o, "cwe-78") == "command_injection"

    def test_unknown_cwe(self):
        o = _outcome()
        assert _resolve_vuln_type(o, "CWE-999") == "other"

    def test_empty(self):
        o = _outcome()
        assert _resolve_vuln_type(o, "") == "other"

    def test_wider_cwe_coverage(self):
        o = _outcome()
        assert _resolve_vuln_type(o, "CWE-426") == "path_traversal"
        assert _resolve_vuln_type(o, "CWE-401") == "memory_leak"
        assert _resolve_vuln_type(o, "CWE-193") == "buffer_overflow"
        assert _resolve_vuln_type(o, "CWE-704") == "other"


class TestExtractCwe:
    def test_from_review_result(self):
        o = _outcome(review_result={"cwe": "CWE-79"})
        assert _extract_cwe(o) == "CWE-79"

    def test_no_review_result(self):
        o = _outcome()
        assert _extract_cwe(o) == ""


class TestValidateFindings:
    def test_no_findings_returns_early(self):
        result = _result(_outcome(status="clean"))
        updated = validate_findings(
            result,
            target_path=Path("/tmp"),
            out_dir=Path("/tmp"),
        )
        assert updated.findings == 0

    @pytest.mark.slow
    def test_emits_findings_and_returns_unchanged(self, tmp_path):
        result = _result(
            _outcome(status="clean"),
            _outcome(file="b.c", function="bar"),
            _outcome(file="c.c", function="baz"),
        )
        updated = validate_findings(
            result,
            target_path=Path("/target"),
            out_dir=tmp_path,
        )
        assert updated.findings == 2
        assert updated.outcomes[0].status == "clean"
        assert updated.outcomes[1].status == "finding"
        assert updated.outcomes[2].status == "finding"

        data = json.loads((tmp_path / "findings.json").read_text())
        assert len(data["findings"]) == 2
        assert data["findings"][0]["file"] == "b.c"
        assert data["findings"][1]["file"] == "c.c"


class TestCopyFindings:
    def test_copies_findings(self, tmp_path):
        src = tmp_path / "findings.json"
        container = {
            "stage": "audit",
            "target_path": "/target",
            "source": "audit",
            "findings": [{"id": f"FIND-{i:03d}"} for i in range(3)],
        }
        src.write_text(json.dumps(container))

        dest = tmp_path / "selected.json"
        _copy_findings_for_validate(src, dest)

        data = json.loads(dest.read_text())
        assert len(data["findings"]) == 3

    def test_truncates_at_max(self, tmp_path, monkeypatch):
        import core.audit.validate as mod
        monkeypatch.setattr(mod, "_MAX_VALIDATE_FINDINGS", 2)

        src = tmp_path / "findings.json"
        container = {
            "stage": "audit",
            "target_path": "/target",
            "source": "audit",
            "findings": [{"id": f"FIND-{i:03d}"} for i in range(5)],
        }
        src.write_text(json.dumps(container))

        dest = tmp_path / "selected.json"
        _copy_findings_for_validate(src, dest)

        data = json.loads(dest.read_text())
        assert len(data["findings"]) == 2


class TestBuildPrompt:
    def test_prompt_contains_key_info(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        validate_dir = tmp_path / "validate"
        validate_dir.mkdir()
        sel = validate_dir / "selected.json"

        prompt = _build_audit_validate_prompt(
            target, audit_dir, validate_dir, sel, 5,
        )

        assert str(target) in prompt
        assert str(audit_dir) in prompt
        assert str(validate_dir) in prompt
        assert str(sel) in prompt
        assert "5 findings" in prompt
        assert "SKILL.md" in prompt
        assert "false positives" in prompt


class TestDispatchValidate:
    def test_skipped_without_claude(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)

        postpass = _dispatch_validate(
            target_path=tmp_path,
            audit_out_dir=tmp_path,
            findings_path=tmp_path / "findings.json",
            findings_count=3,
        )

        assert not postpass.ran
        assert "claude not on PATH" in postpass.skipped_reason

    def test_skipped_on_rule_of_two(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/claude")

        from core.security.rule_of_two import NonInteractiveError
        def mock_require(*args, **kwargs):
            raise NonInteractiveError("no sandbox")
        monkeypatch.setattr(
            "core.security.rule_of_two.require_human_or_sandbox_for_agentic_pass",
            mock_require,
        )

        postpass = _dispatch_validate(
            target_path=tmp_path,
            audit_out_dir=tmp_path,
            findings_path=tmp_path / "findings.json",
            findings_count=3,
        )

        assert not postpass.ran
        assert "no sandbox" in postpass.skipped_reason

    def test_never_raises(self, tmp_path, monkeypatch):
        """Dispatch failures must not break the audit pipeline."""
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/claude")

        def boom(*args, **kwargs):
            raise RuntimeError("kaboom")
        import core.audit.validate as mod
        monkeypatch.setattr(mod, "_dispatch_validate_unsafe", boom)

        postpass = _dispatch_validate(
            target_path=tmp_path,
            audit_out_dir=tmp_path,
            findings_path=tmp_path / "findings.json",
            findings_count=3,
        )

        assert not postpass.ran
        assert "RuntimeError" in postpass.skipped_reason


class TestValidateDefault:
    def test_validate_defaults_to_true(self):
        from core.audit.orchestrator import OrchestratorConfig
        config = OrchestratorConfig(
            target_path=Path("/tmp"),
            out_dir=Path("/tmp"),
        )
        assert config.validate is True


class TestAutoFeedback:
    def test_resolve_annotations_dir_exists(self, tmp_path):
        from core.audit.validate import _resolve_annotations_dir
        ann = tmp_path / "annotations"
        ann.mkdir()
        assert _resolve_annotations_dir(tmp_path) == ann

    def test_resolve_annotations_dir_fallback(self, tmp_path):
        from core.audit.validate import _resolve_annotations_dir
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        result = _resolve_annotations_dir(run_dir)
        assert result == tmp_path / "annotations"

    def test_auto_feedback_no_findings_json(self, tmp_path):
        from core.audit.validate import _auto_feedback
        ann = tmp_path / "annotations"
        ann.mkdir()
        _auto_feedback(
            validate_dir=tmp_path / "validate",
            annotations_dir=ann,
            audit_out_dir=tmp_path,
        )

    def test_auto_feedback_no_annotations_dir(self, tmp_path):
        from core.audit.validate import _auto_feedback
        validate_dir = tmp_path / "validate"
        validate_dir.mkdir()
        (validate_dir / "findings.json").write_text('{"findings": []}')
        _auto_feedback(
            validate_dir=validate_dir,
            annotations_dir=tmp_path / "nonexistent",
            audit_out_dir=tmp_path,
        )
