"""Tests for core.audit.validate — /validate-compatible findings emission."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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

    def test_container_carries_timestamp(self, tmp_path):
        # The hand-rolled emitter had drifted from the canonical
        # FindingsContainer schema: no timestamp. Now built on
        # FindingsContainer.create_empty, which stamps one.
        outcomes = [(0, _outcome())]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        data = json.loads((tmp_path / "findings.json").read_text())
        assert data.get("timestamp")

    def test_emission_round_trips_canonical_dataclasses(self, tmp_path):
        # The strongest contract check: /validate loads this file via
        # FindingsContainer.from_dict — verify the emission survives
        # the round trip with fields in the right places.
        from packages.exploitability_validation.models import (
            FindingsContainer,
        )
        outcomes = [(0, _outcome(body="overflow", hypothesis="off-by-one",
                                 review_result={"cwe": "CWE-120"},
                                 line=42))]
        _emit_findings_json(outcomes, tmp_path, Path("/target"))

        container = FindingsContainer.from_dict(
            json.loads((tmp_path / "findings.json").read_text()))
        assert container.stage == "audit"
        assert container.source == "audit"
        assert len(container.findings) == 1
        f = container.findings[0]
        assert f.id == "FIND-001"
        assert f.line == 42
        assert f.vuln_type == "buffer_overflow"
        assert f.cwe_id == "CWE-120"
        assert f.description == "overflow"
        assert f.origin == "pre_existing"

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
    def test_no_findings_returns_early(self, tmp_path):
        result = _result(_outcome(status="clean"))
        updated = validate_findings(
            result,
            target_path=tmp_path,
            out_dir=tmp_path,
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


class TestDispatchGates:
    """Consolidation fixes: the audit handoff shares /agentic's gate
    chain and truncation policy via core.orchestration.skill_dispatch."""

    def _open_rule_of_two(self, monkeypatch):
        monkeypatch.setattr(
            "core.security.rule_of_two._session_has_human_terminal",
            lambda: True,
        )

    def test_cc_trust_blocks_dispatch(self, tmp_path, monkeypatch):
        # Pre-consolidation the audit handoff had NO cc-trust gate: a
        # repo the operator hadn't trusted for cc dispatch still got a
        # Claude Code child. Now the same gate as /agentic applies.
        self._open_rule_of_two(monkeypatch)
        monkeypatch.setattr(
            "core.security.cc_trust.check_repo_claude_trust",
            lambda repo_path, trust_override=None: True,
        )
        postpass = _dispatch_validate(
            target_path=tmp_path,
            audit_out_dir=tmp_path,
            findings_path=tmp_path / "findings.json",
            findings_count=3,
        )
        assert not postpass.ran
        assert "cc_trust" in postpass.skipped_reason

    def test_trusted_repo_passes_gate(self, tmp_path, monkeypatch):
        # Positive control: gate open -> falls through to the next
        # check (claude not on PATH here).
        self._open_rule_of_two(monkeypatch)
        monkeypatch.setattr(
            "core.security.cc_trust.check_repo_claude_trust",
            lambda repo_path, trust_override=None: False,
        )
        monkeypatch.setattr(
            "core.llm.cc_adapter.resolve_claude_cli",
            lambda explicit=None: None,
        )
        postpass = _dispatch_validate(
            target_path=tmp_path,
            audit_out_dir=tmp_path,
            findings_path=tmp_path / "findings.json",
            findings_count=3,
        )
        assert not postpass.ran
        assert "claude not on PATH" in postpass.skipped_reason

    def test_launch_oserror_reported_as_launch_failure(
            self, tmp_path, monkeypatch):
        # Pre-consolidation only TimeoutExpired was handled around the
        # CC dispatch; an OSError (binary vanished, exec format error)
        # fell through to the generic crash handler. The shared runner
        # classifies it and fails the lifecycle with the reason.
        from unittest.mock import MagicMock, patch

        self._open_rule_of_two(monkeypatch)
        monkeypatch.setattr(
            "core.security.cc_trust.check_repo_claude_trust",
            lambda repo_path, trust_override=None: False,
        )
        monkeypatch.setattr(
            "core.llm.cc_adapter.resolve_claude_cli",
            lambda explicit=None: "/fake/claude",
        )
        run_dir = tmp_path / "validate_run"
        lifecycle_calls = []

        def _lifecycle(cmd, *args, **kwargs):
            argv = cmd if isinstance(cmd, list) else [cmd]
            if Path(argv[0]).name == "raptor-run-lifecycle":
                lifecycle_calls.append(argv[1])
                if argv[1] == "start":
                    run_dir.mkdir(parents=True, exist_ok=True)
                    return MagicMock(returncode=0,
                                     stdout=f"OUTPUT_DIR={run_dir}\n",
                                     stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        def _sandbox(cmd, *args, **kwargs):
            raise OSError("exec format error")

        with patch("core.orchestration.skill_dispatch.subprocess.run",
                   side_effect=_lifecycle), \
             patch("core.orchestration.skill_dispatch."
                   "run_untrusted_networked", side_effect=_sandbox):
            postpass = _dispatch_validate(
                target_path=tmp_path,
                audit_out_dir=tmp_path,
                findings_path=tmp_path / "findings.json",
                findings_count=1,
            )
        assert not postpass.ran
        assert "launch failed" in postpass.skipped_reason
        assert "fail" in lifecycle_calls


class TestSignalSortedTruncation:
    def test_truncation_keeps_strongest_not_head(self, tmp_path,
                                                 monkeypatch):
        # Pre-consolidation the copy head-truncated: with the cap at 2,
        # an is_exploitable finding in position 5 was silently dropped
        # while two weak head entries survived.
        import core.audit.validate as mod
        monkeypatch.setattr(mod, "_MAX_VALIDATE_FINDINGS", 2)

        src = tmp_path / "findings.json"
        findings = [{"id": f"WEAK-{i:03d}"} for i in range(4)]
        findings.append({"id": "STRONG-001", "is_exploitable": True})
        src.write_text(json.dumps({
            "stage": "audit", "target_path": "/t", "source": "audit",
            "findings": findings,
        }))

        dest = tmp_path / "selected.json"
        _copy_findings_for_validate(src, dest)

        kept = [f["id"] for f in json.loads(dest.read_text())["findings"]]
        assert len(kept) == 2
        assert "STRONG-001" in kept

    def test_truncation_orders_by_score(self, tmp_path, monkeypatch):
        import core.audit.validate as mod
        monkeypatch.setattr(mod, "_MAX_VALIDATE_FINDINGS", 1)

        src = tmp_path / "findings.json"
        src.write_text(json.dumps({
            "stage": "audit", "target_path": "/t", "source": "audit",
            "findings": [
                {"id": "LOW", "exploitability_score": 0.2},
                {"id": "HIGH", "exploitability_score": 0.9},
            ],
        }))
        dest = tmp_path / "selected.json"
        _copy_findings_for_validate(src, dest)
        kept = [f["id"] for f in json.loads(dest.read_text())["findings"]]
        assert kept == ["HIGH"]


class TestValidateDefault:
    def test_validate_defaults_to_true(self, tmp_path):
        from core.audit.orchestrator import OrchestratorConfig
        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
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
