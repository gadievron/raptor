"""Tests for core.audit.multi_review — multi-model review substrate."""

from __future__ import annotations

from core.audit.multi_review import (
    AdversarialReviewer,
    AuditModelHandle,
    AuditVerdictAdapter,
    build_task_factory,
    compute_reasoning_divergence,
    consensus_status,
    is_disputed,
    run_audit_multi_review,
    run_self_consistency,
)
from core.llm.multi_model.types import MultiModelResult


def _ctx_stub(_f, _fn):
    return {}


def _review_clean(_ctx, _model):
    return {"status": "clean"}


def _review_finding(_ctx, _model):
    return {"status": "finding"}


class TestAuditModelHandle:
    def test_protocol_compliance(self):
        h = AuditModelHandle(model_name="test-model")
        assert h.model_name == "test-model"

    def test_frozen(self):
        h = AuditModelHandle(model_name="m")
        try:
            h.model_name = "other"
            assert False, "should be frozen"
        except AttributeError:
            pass


class TestAuditVerdictAdapter:
    def setup_method(self):
        self.adapter = AuditVerdictAdapter()

    def test_item_id(self):
        item = {"file": "src/auth.c", "function": "check_pw"}
        assert self.adapter.item_id(item) == "src/auth.c:check_pw"

    def test_item_id_missing_file(self):
        try:
            self.adapter.item_id({"function": "foo"})
            assert False, "should raise"
        except ValueError:
            pass

    def test_normalize_verdict_finding(self):
        assert self.adapter.normalize_verdict({"status": "finding"}) == "positive"

    def test_normalize_verdict_suspicious(self):
        assert self.adapter.normalize_verdict({"status": "suspicious"}) == "positive"

    def test_normalize_verdict_clean(self):
        assert self.adapter.normalize_verdict({"status": "clean"}) == "negative"

    def test_normalize_verdict_dormant(self):
        assert self.adapter.normalize_verdict({"status": "dormant"}) == "inconclusive"

    def test_normalize_verdict_error(self):
        assert self.adapter.normalize_verdict({"status": "error"}) == "unknown"

    def test_normalize_verdict_unknown_status(self):
        assert self.adapter.normalize_verdict({"status": "xyz"}) == "unknown"

    def test_select_primary_prefers_finding_with_majority(self):
        results = [
            {"file": "a.c", "function": "f", "status": "finding"},
            {"file": "a.c", "function": "f", "status": "finding"},
            {"file": "a.c", "function": "f", "status": "clean"},
        ]
        primary = self.adapter.select_primary(results)
        assert primary["status"] == "finding"

    def test_select_primary_lone_finding_downgraded(self):
        results = [
            {"file": "a.c", "function": "f", "status": "clean"},
            {"file": "a.c", "function": "f", "status": "finding"},
            {"file": "a.c", "function": "f", "status": "suspicious"},
        ]
        primary = self.adapter.select_primary(results)
        assert primary["status"] == "suspicious"

    def test_select_primary_two_models_keeps_finding(self):
        results = [
            {"file": "a.c", "function": "f", "status": "clean"},
            {"file": "a.c", "function": "f", "status": "finding"},
        ]
        primary = self.adapter.select_primary(results)
        assert primary["status"] == "finding"

    def test_select_primary_single_item(self):
        results = [{"file": "a.c", "function": "f", "status": "clean"}]
        primary = self.adapter.select_primary(results)
        assert primary["status"] == "clean"

    def test_merge_single_model(self):
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
        }
        merged = self.adapter.merge(per_model)
        assert len(merged) == 1
        assert merged[0]["status"] == "clean"
        # Base-adapter distinct-model gate: a single-model panel is NOT
        # annotated as a multi-model analysis (key absent, not []).
        assert "multi_model_analyses" not in merged[0]
        assert "_model" not in merged[0]

    def test_merge_two_models_full_records(self):
        # Audit consumers read body/hypothesis from the per-model
        # records — the audit adapter overrides the base's truncated
        # record shape.
        per_model = {
            "model-a": [{"file": "a.c", "function": "f",
                         "status": "clean", "body": "looks fine",
                         "hypothesis": ""}],
            "model-b": [{"file": "a.c", "function": "f",
                         "status": "finding", "body": "overflow",
                         "hypothesis": "off-by-one"}],
        }
        merged = self.adapter.merge(per_model)
        analyses = merged[0]["multi_model_analyses"]
        assert {a["model"] for a in analyses} == {"model-a", "model-b"}
        by_model = {a["model"]: a for a in analyses}
        assert by_model["model-b"]["body"] == "overflow"
        assert by_model["model-b"]["hypothesis"] == "off-by-one"
        assert all("_model" not in a for a in analyses)

    def test_merge_skips_malformed_items(self):
        per_model = {
            "model-a": [
                {"status": "finding"},  # no file/function — dropped
                {"file": "a.c", "function": "f", "status": "clean"},
            ],
        }
        merged = self.adapter.merge(per_model)
        assert len(merged) == 1
        assert merged[0]["function"] == "f"

    def test_merge_intra_model_duplicate_is_not_a_panel(self):
        # One model answering twice must not masquerade as
        # a multi-model analysis (the distinct-model gate the
        # hand-rolled merge lacked).
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "clean"},
                {"file": "a.c", "function": "f", "status": "finding"},
            ],
        }
        merged = self.adapter.merge(per_model)
        assert len(merged) == 1
        assert "multi_model_analyses" not in merged[0]

    def test_merge_two_models_agree(self):
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
            "model-b": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
        }
        merged = self.adapter.merge(per_model)
        assert len(merged) == 1
        assert merged[0]["status"] == "clean"
        assert len(merged[0]["multi_model_analyses"]) == 2

    def test_merge_two_models_disagree(self):
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
            "model-b": [
                {"file": "a.c", "function": "f", "status": "finding"}
            ],
        }
        merged = self.adapter.merge(per_model)
        assert len(merged) == 1
        assert merged[0]["status"] == "finding"

    def test_merge_different_functions(self):
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "clean"},
                {"file": "a.c", "function": "g", "status": "finding"},
            ],
        }
        merged = self.adapter.merge(per_model)
        assert len(merged) == 2

    def test_correlate_unanimous_negative(self):
        # Base-adapter correlation shape: agreement_matrix +
        # confidence_signals. Two models agreeing "clean" (negative)
        # is a high-negative signal.
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
            "model-b": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
        }
        merged = self.adapter.merge(per_model)
        corr = self.adapter.correlate(merged, per_model)
        assert corr["confidence_signals"]["a.c:f"] == "high-negative"
        assert corr["summary"]["agreed"] == 1
        assert corr["summary"]["disputed"] == 0

    def test_correlate_unanimous_positive(self):
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "finding"}
            ],
            "model-b": [
                {"file": "a.c", "function": "f", "status": "suspicious"}
            ],
        }
        merged = self.adapter.merge(per_model)
        corr = self.adapter.correlate(merged, per_model)
        assert corr["confidence_signals"]["a.c:f"] == "high"

    def test_correlate_disputed(self):
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
            "model-b": [
                {"file": "a.c", "function": "f", "status": "finding"}
            ],
        }
        merged = self.adapter.merge(per_model)
        corr = self.adapter.correlate(merged, per_model)
        assert corr["confidence_signals"]["a.c:f"] == "disputed"
        assert corr["summary"]["disputed"] == 1

    def test_correlate_majority_split_is_disputed(self):
        # Base semantics: ANY pos+neg mix is a dispute — a 2:1 split
        # still surfaces the dissenting reasoning as a unique insight
        # rather than being smoothed into "majority".
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
            "model-b": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
            "model-c": [
                {"file": "a.c", "function": "f", "status": "finding",
                 "body": "unchecked memcpy length"}
            ],
        }
        merged = self.adapter.merge(per_model)
        corr = self.adapter.correlate(merged, per_model)
        assert corr["confidence_signals"]["a.c:f"] == "disputed"
        # The lone-positive dissent is surfaced for review.
        assert any(i["item_id"] == "a.c:f"
                   for i in corr["unique_insights"])

    def test_correlate_single_model(self):
        per_model = {
            "model-a": [
                {"file": "a.c", "function": "f", "status": "clean"}
            ],
        }
        merged = self.adapter.merge(per_model)
        corr = self.adapter.correlate(merged, per_model)
        assert corr["confidence_signals"]["a.c:f"] == "single_model"


class TestAdversarialReviewer:
    def test_should_review_finding(self):
        def noop_refute(_x):
            return {"refuted": False}

        reviewer = AdversarialReviewer(noop_refute)
        assert reviewer.should_review({"status": "finding"})
        assert reviewer.should_review({"status": "suspicious"})
        assert not reviewer.should_review({"status": "clean"})
        assert not reviewer.should_review({"status": "error"})

    def test_review_not_refuted(self):
        def confirm_refute(_x):
            return {"refuted": False, "reason": "seems legit"}

        reviewer = AdversarialReviewer(confirm_refute)
        items = [{"file": "a.c", "function": "f", "status": "finding",
                  "body": "overflow"}]
        result = reviewer.review(items)
        assert len(result) == 1
        assert result[0]["status"] == "finding"
        assert result[0]["adversarial_review"]["refuted"] is False
        assert "adversarial_downgrade" not in result[0]

    def test_review_refuted_downgrades(self):
        def refuting_fn(_x):
            return {"refuted": True, "reason": "bounds check missed"}

        reviewer = AdversarialReviewer(refuting_fn)
        items = [{"file": "a.c", "function": "f", "status": "finding",
                  "body": "overflow"}]
        result = reviewer.review(items)
        assert result[0]["status"] == "clean"
        assert result[0]["adversarial_downgrade"] is True

    def test_review_exception_doesnt_crash(self):
        def exploding_refute(_item):
            raise RuntimeError("LLM unavailable")

        reviewer = AdversarialReviewer(exploding_refute)
        items = [{"file": "a.c", "function": "f", "status": "finding"}]
        result = reviewer.review(items)
        assert result[0]["status"] == "finding"
        assert "error" in result[0]["adversarial_review"]["reason"]

    def test_cutoff_ratio_default(self):
        reviewer = AdversarialReviewer(_review_clean)
        assert reviewer.cutoff_ratio == 0.85

    def test_cutoff_ratio_custom(self):
        reviewer = AdversarialReviewer(_review_clean, cutoff_ratio=0.95)
        assert reviewer.cutoff_ratio == 0.95


class TestBuildTaskFactory:
    def test_task_returns_single_item(self):
        def ctx_fn(_f, _fn):
            return {"source": "int f() {}"}

        def rev_fn(_ctx, _model):
            return {"status": "clean", "body": "ok"}

        handle = AuditModelHandle(model_name="test")
        task = build_task_factory(ctx_fn, rev_fn, "a.c", "f")
        result = task(handle)
        assert len(result) == 1
        assert result[0]["file"] == "a.c"
        assert result[0]["function"] == "f"
        assert result[0]["status"] == "clean"

    def test_task_preserves_review_fields(self):
        def ctx_fn(_f, _fn):
            return {"source": "void g() {}"}

        def rev_fn(_ctx, _model):
            return {
                "status": "finding",
                "hypothesis": "overflow",
                "evidence_tool": "smt",
            }

        handle = AuditModelHandle(model_name="m1")
        task = build_task_factory(ctx_fn, rev_fn, "b.c", "g")
        result = task(handle)
        assert result[0]["hypothesis"] == "overflow"
        assert result[0]["evidence_tool"] == "smt"

    def test_context_called_once(self):
        call_count = [0]

        def counting_ctx(_f, _fn):
            call_count[0] += 1
            return {}

        task = build_task_factory(counting_ctx, _review_clean, "a.c", "f")
        assert call_count[0] == 1

        h1 = AuditModelHandle(model_name="m1")
        h2 = AuditModelHandle(model_name="m2")
        task(h1)
        task(h2)
        assert call_count[0] == 1


class TestRunAuditMultiReview:
    def test_single_model_clean(self):
        def ctx_fn(_f, _fn):
            return {"source": "int f() { return 0; }"}

        def rev_fn(_ctx, _model):
            return {"status": "clean", "body": "safe"}

        result = run_audit_multi_review(
            file_path="a.c",
            function_name="f",
            models=["model-a"],
            context_fn=ctx_fn,
            review_fn=rev_fn,
        )
        assert len(result.items) == 1
        assert result.items[0]["status"] == "clean"
        assert not result.failed_models

    def test_two_models_agreement(self):
        result = run_audit_multi_review(
            file_path="a.c",
            function_name="f",
            models=["m1", "m2"],
            context_fn=_ctx_stub,
            review_fn=_review_clean,
        )
        assert len(result.items) == 1
        assert result.correlation["summary"]["agreed"] == 1

    def test_two_models_disagreement(self):
        def review_fn(_ctx, model):
            return {"status": "finding" if model == "m1" else "clean"}

        result = run_audit_multi_review(
            file_path="a.c",
            function_name="f",
            models=["m1", "m2"],
            context_fn=_ctx_stub,
            review_fn=review_fn,
        )
        assert result.items[0]["status"] == "finding"
        assert result.correlation["summary"]["disputed"] == 1

    def test_adversarial_refutes(self):
        def refute_fn(_item):
            return {"refuted": True, "reason": "FP"}

        result = run_audit_multi_review(
            file_path="a.c",
            function_name="f",
            models=["m1"],
            context_fn=_ctx_stub,
            review_fn=_review_finding,
            refute_fn=refute_fn,
        )
        assert result.items[0]["status"] == "clean"
        assert result.items[0]["adversarial_downgrade"] is True

    def test_adversarial_confirms(self):
        def refute_fn(_item):
            return {"refuted": False, "reason": "legit"}

        result = run_audit_multi_review(
            file_path="a.c",
            function_name="f",
            models=["m1"],
            context_fn=_ctx_stub,
            review_fn=_review_finding,
            refute_fn=refute_fn,
        )
        assert result.items[0]["status"] == "finding"

    def test_no_adversarial_for_clean(self):
        refute_calls = [0]

        def refute_fn(_item):
            refute_calls[0] += 1
            return {"refuted": True}

        run_audit_multi_review(
            file_path="a.c",
            function_name="f",
            models=["m1"],
            context_fn=_ctx_stub,
            review_fn=_review_clean,
            refute_fn=refute_fn,
        )
        assert refute_calls[0] == 0


    def test_empty_models_raises(self):
        try:
            run_audit_multi_review(
                file_path="a.c",
                function_name="f",
                models=[],
                context_fn=_ctx_stub,
                review_fn=_review_clean,
            )
            assert False, "should raise ValueError"
        except ValueError as exc:
            assert "empty" in str(exc)


class TestConsensusStatus:
    def test_returns_status(self):
        result = MultiModelResult(
            items=[{"status": "finding"}],
        )
        assert consensus_status(result) == "finding"

    def test_empty_returns_none(self):
        result = MultiModelResult()
        assert consensus_status(result) is None


class TestIsDisputed:
    def test_disputed(self):
        result = MultiModelResult(
            correlation={"confidence_signals": {"a.c:f": "disputed"}},
        )
        assert is_disputed(result) is True

    def test_unanimous(self):
        result = MultiModelResult(
            correlation={"confidence_signals": {"a.c:f": "high"}},
        )
        assert is_disputed(result) is False

    def test_no_correlation(self):
        result = MultiModelResult()
        assert is_disputed(result) is False


class TestRunSelfConsistency:
    def test_basic_consistency(self):
        result = run_self_consistency(
            file_path="a.c",
            function_name="f",
            model="test-model",
            n_samples=3,
            context_fn=_ctx_stub,
            review_fn=_review_clean,
        )
        assert len(result.items) == 1
        analyses = result.items[0].get("multi_model_analyses", [])
        assert len(analyses) == 3
        assert all("test-model" in a["model"] for a in analyses)

    def test_n_samples_too_low(self):
        try:
            run_self_consistency(
                file_path="a.c",
                function_name="f",
                model="test-model",
                n_samples=1,
                context_fn=_ctx_stub,
                review_fn=_review_clean,
            )
            assert False, "should raise ValueError"
        except ValueError as exc:
            assert "n_samples" in str(exc)

    def test_majority_vote(self):
        call_count = [0]

        def alternating_review(_ctx, _model):
            call_count[0] += 1
            return {"status": "finding" if call_count[0] <= 2 else "clean"}

        result = run_self_consistency(
            file_path="a.c",
            function_name="f",
            model="m",
            n_samples=3,
            context_fn=_ctx_stub,
            review_fn=alternating_review,
        )
        assert result.items[0]["status"] == "finding"

    def test_with_adversarial(self):
        def refute_fn(_item):
            return {"refuted": True, "reason": "FP"}

        result = run_self_consistency(
            file_path="a.c",
            function_name="f",
            model="m",
            n_samples=2,
            context_fn=_ctx_stub,
            review_fn=_review_finding,
            refute_fn=refute_fn,
        )
        assert result.items[0].get("adversarial_downgrade") is True


class TestComputeReasoningDivergence:
    def test_empty_result(self):
        result = MultiModelResult()
        assert compute_reasoning_divergence(result) is None

    def test_single_model(self):
        result = MultiModelResult(
            items=[{
                "status": "clean",
                "multi_model_analyses": [
                    {"model": "m1", "body": "looks safe"},
                ],
            }],
        )
        assert compute_reasoning_divergence(result) is None

    def test_no_bodies(self):
        result = MultiModelResult(
            items=[{
                "status": "clean",
                "multi_model_analyses": [
                    {"model": "m1"},
                    {"model": "m2"},
                ],
            }],
        )
        assert compute_reasoning_divergence(result) is None

    def test_with_divergent_reasoning(self, monkeypatch):
        import core.llm.semantic_entropy as se_mod

        def fake_divergence(reasonings, min_models=2):
            return {
                "mean_jaccard_distance": 0.8,
                "pair_distances": {"m1-m2": 0.8},
            }

        monkeypatch.setattr(se_mod, "divergence", fake_divergence)

        result = MultiModelResult(
            items=[{
                "status": "clean",
                "multi_model_analyses": [
                    {"model": "m1", "body": "safe because of bounds check"},
                    {"model": "m2", "body": "safe because of type constraint"},
                ],
            }],
        )
        div = compute_reasoning_divergence(result)
        assert div is not None
        assert div["mean_jaccard_distance"] == 0.8

    def test_uses_reasoning_field_fallback(self, monkeypatch):
        import core.llm.semantic_entropy as se_mod

        captured = {}

        def fake_divergence(reasonings, min_models=2):
            captured["reasonings"] = reasonings
            return {"mean_jaccard_distance": 0.1}

        monkeypatch.setattr(se_mod, "divergence", fake_divergence)

        result = MultiModelResult(
            items=[{
                "status": "clean",
                "multi_model_analyses": [
                    {"model": "m1", "reasoning": "reason A"},
                    {"model": "m2", "reasoning": "reason B"},
                ],
            }],
        )
        compute_reasoning_divergence(result)
        assert "m1" in captured["reasonings"]
        assert captured["reasonings"]["m1"] == "reason A"
