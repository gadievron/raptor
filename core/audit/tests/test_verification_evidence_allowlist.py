"""Verification evidence gate wrapper and reuse exemption pins.

The evidence-grade firewall recognises a part only when
``is_tool_evidence`` AND not ``_is_detection_only``; everything unknown
fails closed. The gate wrapper (``_is_verification_evidence_for_gate``)
delegates the composite parse whole.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.audit.evidence_grade import sanitize_llm_evidence_tool
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _is_verification_evidence_for_gate,
    _resolve_gate_demoted,
)
def _row(evidence: str, **overrides: Any) -> ReviewOutcome:
    kwargs: dict[str, Any] = {
        "file": "src/user.go",
        "function": "SetUser",
        "status": "suspicious",
        "body": "review prose",
        "evidence_tool": evidence,
        "review_result": {"evidence_tool": evidence},
    }
    kwargs.update(overrides)
    return ReviewOutcome(**kwargs)


class TestGateWrapper:
    """The gate wrapper delegates the composite parse whole."""

    def test_pipeline_receipt_qualifies(self) -> None:
        assert _is_verification_evidence_for_gate(
            _row("smt:check-overflow"),
        )

    def test_claim_tail_does_not_leak(self) -> None:
        # Split-and-scan handed the "joern" tail of one sanitized model
        # answer to the classifier as a standalone part.
        assert not _is_verification_evidence_for_gate(
            _row(sanitize_llm_evidence_tool("smt+joern")),
        )

    def test_unknown_namespace_does_not_exempt(self) -> None:
        assert not _is_verification_evidence_for_gate(
            _row("journal:recall:run-3"),
        )


def _make_result(*outcomes: ReviewOutcome) -> OrchestratorResult:
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
    r.clean = sum(1 for o in outcomes if o.status == "clean")
    r.findings = sum(1 for o in outcomes if o.status == "finding")
    return r


def _config(tmp_path: Path) -> OrchestratorConfig:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "user.go").write_text(
        "package cfg\n\nfunc SetUser(s string) uint32 { return 0 }\n",
    )
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=target, out_dir=out)


def _reused_suspicious() -> ReviewOutcome:
    o = _row(
        "journal:recall:audit-20260901-120000",
        body="[reused: verdict imported from run audit-20260901-120000; "
             "source hash unchanged]\n\nprior review prose",
        review_result={
            "status": "suspicious",
            "reused": True,
            "reused_from_run": "audit-20260901-120000",
        },
    )
    o.reused = True
    o.reused_from_run = "audit-20260901-120000"
    return o


class TestReusedSuspiciousSurvivesResolution:
    """The end-of-run resolution pass honours the reuse exemption.

    A reused suspicious row's ``journal:recall:*`` provenance is a
    deliberate downgrade (LLM_ONLY tier cap until a live tool
    re-confirms), not an admission that nothing supports the verdict —
    no lane in THIS run adjudicated the row, so this run's silence must
    not decay it. Same exemption, same authority
    (``promotion_alarm.is_reuse_exempt``) as the journal-write and
    findings-export chokepoints.
    """

    def test_reused_suspicious_kept(self, tmp_path: Path) -> None:
        result = _make_result(_reused_suspicious())
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist={},
            available_tools={"joern": True},
        )
        assert result.outcomes[0].status == "suspicious"
        assert result.suspicious == 1

    def test_same_row_without_reuse_marks_resolves(
        self, tmp_path: Path,
    ) -> None:
        # Discriminating counterpart: strip the pipeline-set reuse
        # fields and the identical evidence-free row IS resolved —
        # proving the survival above comes from the exemption, not
        # from the stamp accidentally grading as verification.
        row = _reused_suspicious()
        row.reused = False
        row.reused_from_run = ""
        result = _make_result(row)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist={},
            available_tools={"joern": True},
        )
        assert result.outcomes[0].status != "suspicious"
