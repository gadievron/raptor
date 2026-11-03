"""Verification evidence is an allowlist, not a blocklist.

``_is_verification_evidence`` is the merge-tie breaker: it decides
whether a stamp is strong enough for the conservative ensemble merge to
keep a suspicious row against a clean sibling, and (via the gate
wrapper) whether an evidence-free-suspicious resolution pass may touch
a row. The old shape rejected two known-bad prefixes and accepted
everything else — a stamp in a namespace no producer table had ever
heard of counted as verification. These pins hold the inverted
direction: a part qualifies only when the evidence-grade firewall
recognises it (``is_tool_evidence``) AND it is not detection-role
(``_is_detection_only``); everything unknown fails closed. The one
receipt kind with no qualifying single part — the Bayesian
aggregation-promotion composite (``"+".join(confirmed)``, >=2 distinct
detection-role namespaces jointly crossing the confirm threshold) —
qualifies via the whole-stamp rule, but never when an ``llm-claimed:``
or ``prefilter:`` part contaminates the composite.

Composite boundary: ``sanitize_llm_evidence_tool`` namespaces the
model's WHOLE raw answer, so in a mixed stamp everything from the first
``llm-claimed:`` part onward is claim text, not receipts. A genuine
receipt ahead of the marker (the evidence-combine shape) keeps its
status; a claim tail (``llm-claimed:smt+joern``) earns nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from core.audit.evidence_grade import sanitize_llm_evidence_tool
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _is_verification_evidence_for_gate,
    _resolve_gate_demoted,
)
from core.audit.pipeline import _is_verification_evidence, _merge_outcomes


class TestVerificationAllowlist:
    """Direct pins on the classifier, both directions."""

    @pytest.mark.parametrize("stamp", [
        # Verification-role receipts from registered producers.
        "smt:check-integer-narrowing",
        "smt:check-overflow",
        "smt:check-integer-narrowing:witness",
        "semgrep:go-parse-int-narrowing",
        "joern:flow",
        # Provenance wrapper around a real receipt: the wrapper is
        # history, the wrapped stamp is the evidence.
        "clean-refuted:smt",
        # Evidence-combine shape: the surviving side's receipt leads,
        # the discarded side's sanitized claim rides behind it.
        "smt:check-integer-narrowing+llm-claimed:smt",
        # Bayesian aggregation-promotion receipt
        # (_aggregate_channel_confirmations mints "+".join(confirmed)
        # after >=2 independent detection-role channels jointly cross
        # the confirm threshold): no single part suffices — by
        # construction — but the composite is a genuine confirmation.
        "consistency:cwe190-majority+fail_open:handler-outcome-naming",
        # Same rule when one channel's namespace is also a registered
        # tool namespace (stock cocci detection rule + detection SMT
        # verb: two distinct detection-role channels).
        "coccinelle:missing_bounds_check+smt:check-toctou",
    ])
    def test_verification(self, stamp: str) -> None:
        assert _is_verification_evidence(stamp), stamp

    @pytest.mark.parametrize("stamp", [
        "",
        # Unknown namespace: no producer table names it — fail closed,
        # however confident it sounds.
        "futuretool:confirmed",
        # Provenance-only stamps whose own doctrine forbids breaking a
        # merge tie: cross-run reuse ("journal:recall is not tool
        # evidence"), SAGE recall, dead-code / preprocessor verdict
        # provenance, guard-sufficiency clean marks, silent-SARIF marks.
        "journal:recall:run-3",
        "sage:recall:prior-audit",
        "reachability:dead_code",
        "inventory:preprocessor_dead",
        "mechanical:guard_sufficiency",
        "sarif:no_alerts",
        # Detection-role receipts corroborate, never convict (stock
        # cocci rule with ``// @role: detection`` metadata; SMT verb
        # the role table demotes).
        "smt:check-toctou",
        "coccinelle:missing_bounds_check",
        # Model-authored values.
        "llm-claimed:smt",
        "Semgrep",
        "manual",
        # Claim tail: the model wrote "smt+joern"; the sanitizer
        # namespaces the whole answer, so the "joern" part is claim
        # text, not a receipt.
        "llm-claimed:smt+joern",
        # The surviving side's provenance leads: a stamp headed by a
        # non-mechanical part never qualifies, whatever follows.
        "prefilter:sink-scan+semgrep:rule",
        # One channel confirming twice is one observation, not an
        # aggregation (same-engine receipts are correlated — the
        # producer's own distinct-namespace floor).
        "smt:check-toctou+smt:check-auth-bypass",
        # Contaminated composites never ride the aggregation rule: an
        # llm-claimed: part anywhere means the tail is claim text, and
        # a prefilter: part means this is not the pristine
        # "+".join(confirmed) receipt the producer mints.
        "consistency:cwe190-majority+llm-claimed:x+fail_open:handler-outcome-naming",
        "consistency:cwe190-majority+prefilter:sink-scan+fail_open:handler-outcome-naming",
        "llm-claimed:x+consistency:cwe190-majority+fail_open:handler-outcome-naming",
    ])
    def test_not_verification(self, stamp: str) -> None:
        assert not _is_verification_evidence(stamp), stamp

    def test_sanitized_claim_tail_matches_pipeline_shape(self) -> None:
        # The claim-tail pin above, derived the way the pipeline
        # actually mints it rather than hand-written.
        stamp = sanitize_llm_evidence_tool("smt+joern")
        assert stamp == "llm-claimed:smt+joern"
        assert not _is_verification_evidence(stamp)


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
            _row("smt:check-integer-narrowing"),
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


_AGG_STAMP = "consistency:cwe190-majority+fail_open:handler-outcome-naming"


class TestAggregationMergeTieBreak:
    """The aggregation receipt survives the ensemble merge end-to-end.

    ``_aggregate_channel_confirmations`` promotes a row only after >=2
    independent detection-role channels jointly cross the posterior
    threshold, and ``_record_aggregated_promotion`` stamps the receipt.
    The ``_merge_outcomes`` tie-break must treat that composite as
    verification: a clean sibling lane must not flatten a
    threshold-crossed confirmation (and its evidence must not be
    erased). The contaminated counterpart pins the boundary — the same
    channels with a model-authored part spliced in are NOT the
    producer's receipt and earn nothing.
    """

    def test_aggregation_stamped_suspicious_survives_clean_sibling(
        self,
    ) -> None:
        row = _row(_AGG_STAMP)
        clean = ReviewOutcome(
            file="src/user.go", function="SetUser",
            status="clean", body="clean lane",
        )
        merged = _merge_outcomes([row], [clean])
        assert merged[0].status == "suspicious"
        assert _AGG_STAMP in (merged[0].evidence_tool or "")

    def test_contaminated_composite_does_not_break_the_tie(self) -> None:
        row = _row(
            "consistency:cwe190-majority+llm-claimed:x"
            "+fail_open:handler-outcome-naming",
        )
        clean = ReviewOutcome(
            file="src/user.go", function="SetUser",
            status="clean", body="clean lane",
        )
        merged = _merge_outcomes([row], [clean])
        assert merged[0].status == "clean"


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
