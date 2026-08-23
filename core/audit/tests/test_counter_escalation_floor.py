"""Counter-escalation evidence floor — end-of-run gate resolution.

A counter-hypothesis escalation keeps a model-clean verdict alive as
``suspicious`` so deepen/verification can convict. When the run ends
with no receipt, the floor restores the model's own clean verdict:
a machine-raised suspicious with zero receipts is not a model claim
and must not ship as one (live case: a cocci missing_bounds_check
lead on a correct strlcpy-shaped bounded-copy helper seeded a review
that concluded clean; the escalation re-armed the verdict off a
caller-contract counter and the pattern lead then retained it to
export).

Pinned here:
- receipt-less counter-escalated suspicious resolves to clean even
  when pattern-prior corroboration (pre-sweep detector hits, prefilter
  sink scans) flags the function, and independently of Joern;
- verification-role evidence and fired probes retain suspicious (the
  demotion-referee floor is preserved);
- model-emitted suspicious never carries the flag and is untouched;
- the review path stamps the structured ``counter_escalated`` flag.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _is_counter_escalated,
    _is_machine_raised,
    _resolve_gate_demoted,
)

ESCALATION_BODY = (
    "[counter-hypothesis escalation: the review rationale below "
    "concludes clean, but a compelling counter-hypothesis kept this "
    "verdict suspicious — A caller could pass a capacity larger than "
    "the actual destination allocation]\n\nSTEP 5 — VERDICT\nClean."
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
    # memcpy in source: the prefilter sink scan flags this function,
    # so under pattern-prior retention the outcome would have stayed
    # suspicious — the floor must resolve it without consulting priors.
    (target / "copy.c").write_text(
        "size_t bounded_copy(char *dst, size_t cap,\n"
        "        const char *src, size_t len) {\n"
        "    if (cap == 0) return 0;\n"
        "    size_t n = len < cap - 1 ? len : cap - 1;\n"
        "    memcpy(dst, src, n);\n"
        "    dst[n] = '\\0';\n"
        "    return n;\n"
        "}\n"
    )
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=target, out_dir=out)


_CHECKLIST = {
    "files": [{
        "path": "copy.c",
        "items": [{
            "name": "bounded_copy",
            "line_start": 1,
            "line_end": 8,
        }],
    }],
}

_MECHANICAL_FINDINGS = {
    "copy.c:bounded_copy": [{
        "file": "copy.c",
        "function": "bounded_copy",
        "detector": "cocci:missing_bounds_check",
        "line": 6,
        "description": "Array 'dst' indexed by 'n' without prior bounds check",
    }],
}


def _escalated_outcome(**overrides: Any) -> ReviewOutcome:
    kwargs: dict[str, Any] = {
        "file": "copy.c",
        "function": "bounded_copy",
        "status": "suspicious",
        "body": ESCALATION_BODY,
        "hypothesis": "overflows dst if len exceeds cap - 1",
        "evidence_tool": "",
        "review_result": {"counter_escalated": True, "cwe": "CWE-787"},
        "line": 1,
    }
    kwargs.update(overrides)
    return ReviewOutcome(**kwargs)


class TestCounterEscalationFloor:
    def test_receiptless_resolves_clean_despite_pattern_corroboration(
        self, tmp_path: Path,
    ):
        """The failing lane: zero receipts + pre-sweep cocci lead +
        prefilter sink hit — the machine-raised suspicious must resolve
        clean."""
        outcome = _escalated_outcome()
        result = _make_result(outcome)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist=_CHECKLIST,
            available_tools={"joern": True},
            mechanical_findings=_MECHANICAL_FINDINGS,
        )
        assert result.outcomes[0].status == "clean"
        assert result.outcomes[0].body.startswith(
            "[machine-escalation resolution:",
        )
        assert result.suspicious == 0
        assert result.clean == 1

    def test_resolves_clean_when_joern_down(self, tmp_path: Path):
        """The floor is not gated on Joern availability — the review's
        own completed refutation ladder is the basis, not a tool run."""
        outcome = _escalated_outcome()
        result = _make_result(outcome)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist=_CHECKLIST,
            available_tools=None,
            mechanical_findings=_MECHANICAL_FINDINGS,
        )
        assert result.outcomes[0].status == "clean"

    def test_never_resolves_dark(self, tmp_path: Path):
        """The review completed and concluded clean — 'no channel ever
        looked' is false, so the floor must not route to dark."""
        outcome = _escalated_outcome()
        result = _make_result(outcome)
        _resolve_gate_demoted(
            result, _make_toolless_config(tmp_path),
            sarif_cache=None, checklist={},
            available_tools={"joern": True},
            mechanical_findings=None,
        )
        assert result.outcomes[0].status == "clean"

    def test_verification_evidence_retains_suspicious(self, tmp_path: Path):
        outcome = _escalated_outcome(evidence_tool="dynamic:sanitizer")
        result = _make_result(outcome)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist=_CHECKLIST,
            available_tools={"joern": True},
            mechanical_findings=None,
        )
        assert result.outcomes[0].status == "suspicious"
        assert result.suspicious == 1

    def test_detection_probe_does_not_retain_machine_raised(
        self, tmp_path: Path,
    ):
        """Doctrine update (corpus-verified): a machine-raised
        suspicious retains ONLY on verification-grade evidence. An
        llm-claimed probe reference (or a detection-role heuristic
        confirm) merely echoes the speculation the model already
        adjudicated clean — the observed kernel FP family was exactly
        this shape, unresolvable by any later lane."""
        outcome = _escalated_outcome(
            evidence_tool="llm-claimed:smt: overflow condition sat",
        )
        outcome.tools_dispatched = {"smt"}
        result = _make_result(outcome)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist=_CHECKLIST,
            available_tools={"joern": True},
            mechanical_findings=None,
        )
        assert result.outcomes[0].status == "clean"

    def test_verification_receipt_retains_machine_raised(
        self, tmp_path: Path,
    ):
        """Verification-role evidence still retains: the demotion
        referee for authoritative receipts is unchanged."""
        outcome = _escalated_outcome(
            evidence_tool="smt:check-overflow",
        )
        outcome.tools_dispatched = {"smt"}
        result = _make_result(outcome)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist=_CHECKLIST,
            available_tools={"joern": True},
            mechanical_findings=None,
        )
        assert result.outcomes[0].status == "suspicious"
        assert result.suspicious == 1

    def test_model_emitted_suspicious_untouched(self, tmp_path: Path):
        """A genuine LLM-suspicious lead (no escalation flag) never hits
        the floor: with Joern down the legacy path leaves it alone."""
        outcome = ReviewOutcome(
            file="copy.c",
            function="bounded_copy",
            status="suspicious",
            body="STEP 5 — VERDICT\nSuspicious: unbounded length reaches memcpy.",
            hypothesis="overflows dst if len exceeds cap - 1",
            evidence_tool="",
            review_result={"cwe": "CWE-787"},
            line=1,
        )
        result = _make_result(outcome)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist=_CHECKLIST,
            available_tools=None,
            mechanical_findings=None,
        )
        assert result.outcomes[0].status == "suspicious"
        assert result.suspicious == 1

    def test_model_emitted_suspicious_with_corroboration_stays(
        self, tmp_path: Path,
    ):
        """Lead preservation with Joern up: pattern corroboration still
        retains a MODEL-emitted suspicious (pre-existing behavior)."""
        outcome = ReviewOutcome(
            file="copy.c",
            function="bounded_copy",
            status="suspicious",
            body="Suspicious: unbounded length reaches memcpy.",
            hypothesis="overflows dst if len exceeds cap - 1",
            evidence_tool="",
            review_result={"cwe": "CWE-787"},
            line=1,
        )
        result = _make_result(outcome)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist=_CHECKLIST,
            available_tools={"joern": True},
            mechanical_findings=_MECHANICAL_FINDINGS,
        )
        assert result.outcomes[0].status == "suspicious"

    def test_body_prefix_fallback_without_review_result(self, tmp_path: Path):
        """Outcomes rebuilt from journal/checkpoint may lack
        review_result — the escalation body prefix still qualifies."""
        outcome = _escalated_outcome(review_result=None)
        result = _make_result(outcome)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist=_CHECKLIST,
            available_tools=None,
            mechanical_findings=None,
        )
        assert result.outcomes[0].status == "clean"


def _make_toolless_config(tmp_path: Path) -> OrchestratorConfig:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "copy.c").write_text("int f(void) { return 0; }\n")
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=target, out_dir=out)


class TestIsCounterEscalated:
    def test_structured_flag(self):
        assert _is_counter_escalated(_escalated_outcome(body="anything"))

    def test_body_prefix(self):
        assert _is_counter_escalated(_escalated_outcome(review_result=None))

    def test_plain_suspicious_is_not(self):
        outcome = _escalated_outcome(
            body="Suspicious: memcpy length unchecked.",
            review_result={"cwe": "CWE-787"},
        )
        assert not _is_counter_escalated(outcome)


class TestReviewPathStampsFlag:
    """make_review_fn persists the machine-raised provenance on
    review_result so gate resolution (and journal replay) can see it."""

    def test_escalation_stamps_counter_escalated(self, tmp_path: Path):
        from core.audit.llm_review import make_review_fn
        from core.audit.tests.test_llm_review import FakeLLMClient

        client = FakeLLMClient({
            "status": "clean",
            "body": "STEP 5 — VERDICT\nClean.",
            "hypothesis": "overflows dst if len exceeds cap - 1",
            "counter_hypothesis": (
                "A caller could pass a capacity larger than the actual "
                "destination allocation or a length larger than the "
                "source allocation, turning the guarded copy into an "
                "overflow or over-read despite correct internal "
                "clamping."
            ),
            "counter_direction": "supports_vuln",
            # One non-refuted hypothesis keeps the all-refuted demotion
            # out of the way — the exact shape of the failing lane.
            "hypotheses": [
                {"mechanism": "memcpy overflow", "confidence": "refuted"},
                {"mechanism": "src over-read via caller", "confidence": "low"},
            ],
        })
        review_fn = make_review_fn(client)
        config = _make_toolless_config(tmp_path)
        outcome = review_fn(
            {
                "file": "copy.c",
                "function": "bounded_copy",
                "line_start": 1,
                "line_end": 8,
                "source": "size_t bounded_copy(void) { return 0; }",
            },
            config,
        )
        assert outcome.status == "suspicious"
        assert outcome.body.startswith("[counter-hypothesis escalation:")
        assert outcome.review_result["counter_escalated"] is True
        assert _is_counter_escalated(outcome)


class TestAntiSelfRefutationRows:
    """The anti-self-refutation gate's escalations are machine-raised
    too — same producer class (model-clean, machine-suspicious), same
    end-of-run doctrine."""

    ASR_BODY = (
        "[anti_self_refutation: hypothesis 'use after free of the ctx' "
        "self-refuted without mechanical evidence; concurrency/"
        "lifecycle self-refutations are unreliable]\n\nVerdict: clean."
    )

    def test_prefix_counts_as_machine_raised(self):
        o = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body=self.ASR_BODY,
        )
        assert _is_machine_raised(o)
        assert not _is_counter_escalated(o)

    def test_receiptless_asr_row_resolves_clean(self, tmp_path: Path):
        o = ReviewOutcome(
            file="copy.c", function="bounded_copy", status="suspicious",
            body=self.ASR_BODY,
        )
        result = _make_result(o)
        _resolve_gate_demoted(
            result, _config(tmp_path),
            sarif_cache=None, checklist=_CHECKLIST,
            available_tools={"joern": True},
            mechanical_findings=None,
        )
        assert result.outcomes[0].status == "clean"
