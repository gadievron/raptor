"""Demotion referee: probe-backed suspicious vs LLM-only refutation.

A suspicious verdict backed by a fired detection-role probe (SMT
verb, coccinelle rule — including mid-loop receipts recorded under
``llm-claimed:`` with the dispatch record as witness) may not be
demoted to clean/dark on an LLM argument alone. Only a
verification-role refuter may answer a tool observation.
"""

from pathlib import Path

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _deepen_demotion_refereed,
    _probe_backed_suspicious,
    _resolve_gate_demoted,
)


def _outcome(status="suspicious", evidence="", dispatched=None, **kw):
    o = ReviewOutcome(
        file=kw.pop("file", "a.c"),
        function=kw.pop("function", "f"),
        status=status,
        body=kw.pop("body", "review prose"),
        evidence_tool=evidence,
        **kw,
    )
    if dispatched is not None:
        o.tools_dispatched = set(dispatched)
    return o


class TestProbeBackedSuspicious:
    def test_bare_tool_receipt_qualifies(self):
        # Exemplar is a verification-role verb; the lexical heuristics
        # (check-toctou / check-early-release ...) are detection-role
        # and no longer qualify alone.
        assert _probe_backed_suspicious(
            _outcome(evidence="smt:check-overflow"),
        )

    def test_composite_detection_receipt_qualifies(self):
        assert _probe_backed_suspicious(
            _outcome(
                evidence=(
                    "smt:invariant-preservation"
                    "+coccinelle:missing_bounds_check"
                ),
            ),
        )

    def test_llm_claimed_with_dispatch_witness_qualifies(self):
        assert _probe_backed_suspicious(
            _outcome(
                evidence="llm-claimed:smt:check-toctou (mid-loop)",
                dispatched={"smt"},
            ),
        )

    def test_llm_claimed_without_dispatch_witness_rejected(self):
        assert not _probe_backed_suspicious(
            _outcome(
                evidence="llm-claimed:smt:check-toctou (mid-loop)",
                dispatched=set(),
            ),
        )

    def test_llm_claimed_wrong_family_rejected(self):
        assert not _probe_backed_suspicious(
            _outcome(
                evidence="llm-claimed:smt:check-toctou",
                dispatched={"coccinelle"},
            ),
        )

    def test_prefilter_never_qualifies(self):
        assert not _probe_backed_suspicious(
            _outcome(evidence="prefilter:array-index-unchecked"),
        )

    def test_free_form_claim_never_qualifies(self):
        assert not _probe_backed_suspicious(
            _outcome(evidence="llm-claimed:careful reading of the loop"),
        )

    def test_empty_evidence_rejected(self):
        assert not _probe_backed_suspicious(_outcome(evidence=""))


class TestDeepenDemotionReferee:
    def _deepen_clean(self, structured=True, evidence=""):
        rr = {}
        if structured:
            rr["all_refuted_demotion"] = True
        return _outcome(
            status="clean", evidence=evidence, review_result=rr,
        )

    def _probe_backed_prior(self):
        return _outcome(
            status="suspicious",
            evidence="llm-claimed:smt:check-toctou (mid-loop)",
            dispatched={"smt"},
        )

    def test_llm_only_all_refuted_demotion_blocked(self):
        assert _deepen_demotion_refereed(
            self._probe_backed_prior(), self._deepen_clean(),
        )

    def test_rationale_consistency_demotion_blocked_too(self):
        clean = _outcome(
            status="clean",
            review_result={"rationale_consistency_demotion": True},
        )
        assert _deepen_demotion_refereed(self._probe_backed_prior(), clean)

    def test_unstructured_clean_not_refereed(self):
        # The dominated branch already keeps the prior for these.
        assert not _deepen_demotion_refereed(
            self._probe_backed_prior(), self._deepen_clean(structured=False),
        )

    def test_probe_less_prior_not_refereed(self):
        prior = _outcome(status="suspicious", evidence="")
        assert not _deepen_demotion_refereed(prior, self._deepen_clean())

    def test_non_clean_deepen_not_refereed(self):
        deeper = _outcome(
            status="suspicious",
            review_result={"all_refuted_demotion": True},
        )
        assert not _deepen_demotion_refereed(
            self._probe_backed_prior(), deeper,
        )

    def test_verification_refuter_allows_demotion(self):
        clean = self._deepen_clean(evidence="dynamic:sanitizer")
        from core.audit.pipeline import _is_verification_evidence
        if _is_verification_evidence("dynamic:sanitizer"):
            assert not _deepen_demotion_refereed(
                self._probe_backed_prior(), clean,
            )


class TestResolutionRefereesProbeBacked:
    def _setup(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x; }\n")
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [{
                "path": "a.c",
                "items": [{"name": "f", "line_start": 1, "line_end": 1}],
            }],
        }
        config = OrchestratorConfig(target_path=target, out_dir=out)
        return config, checklist

    def _result(self, *outcomes):
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
        r.clean = sum(1 for o in outcomes if o.status == "clean")
        return r

    def test_probe_backed_suspicious_not_resolved(self, tmp_path):
        config, checklist = self._setup(tmp_path)
        outcome = _outcome(
            evidence="llm-claimed:smt:check-toctou (mid-loop)",
            dispatched={"smt"},
            line=1,
        )
        result = self._result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
            available_tools={"joern": True},
        )
        assert result.outcomes[0].status == "suspicious"
        assert result.suspicious == 1

    def test_probe_less_suspicious_still_resolves(self, tmp_path):
        config, checklist = self._setup(tmp_path)
        outcome = _outcome(evidence="", line=1)
        result = self._result(outcome)
        _resolve_gate_demoted(
            result, config, sarif_cache=None, checklist=checklist,
            available_tools={"joern": True},
        )
        assert result.outcomes[0].status in ("clean", "dark")
        assert result.suspicious == 0


class TestSingleDetectionReceiptFloor:
    """A single detection-role receipt may not hold the referee floor
    (observed sustaining clean-expected kernel functions against
    structured deepen demotions); two independent detection namespaces
    — the aggregation shape — still hold, as does any
    verification-role receipt."""

    def test_single_detection_receipt_does_not_qualify(self):
        assert not _probe_backed_suspicious(
            _outcome(evidence="smt:check-lock-domain"),
        )

    def test_verification_receipt_still_qualifies(self):
        assert _probe_backed_suspicious(
            _outcome(evidence="smt:check-null-deref"),
        )

    def test_demoted_heuristic_verbs_do_not_qualify_alone(self):
        # The corpus FP family: lexical flow heuristics held
        # verification role and their lone receipts retained
        # machine-raised suspicious rows forever.
        for verb in ("check-early-release", "check-toctou",
                     "check-auth-bypass", "check-resource-leak",
                     "check-null-propagation"):
            assert not _probe_backed_suspicious(
                _outcome(evidence=f"smt:{verb}"),
            ), verb

    def test_same_namespace_detection_pair_does_not_qualify(self):
        assert not _probe_backed_suspicious(
            _outcome(
                evidence="smt:check-lock-domain+smt:invariant-preservation",
            ),
        )
