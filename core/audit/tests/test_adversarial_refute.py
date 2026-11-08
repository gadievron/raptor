"""Tests for the real adversarial refuter (--adversarial).

Previously ``--adversarial`` set ``adversarial_target`` in a context
dict that no prompt builder consumed — the "refutation" was an
independent re-review of identical context and "refuted" meant the
second sample happened to say clean. These tests pin the replacement:
a purpose-built refutation prompt (envelope-disciplined), structured
refuted/stands/needs_evidence judgments, unverified objections that cannot
change verdicts, and existing routing for needs_evidence. All LLM calls
are stubbed; no new verification is dispatched by the critic.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from types import SimpleNamespace

from core.audit.adversarial_refute import (
    VERDICT_NEEDS_EVIDENCE,
    VERDICT_REFUTED,
    VERDICT_STANDS,
    build_refutation_prompt,
    parse_refutation,
    pick_refuter_model,
    run_refutation,
)
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _adversarial_refute_pass,
    _multi_pass_review,
    _run_dark_verification,
)


class _StubResponse:
    def __init__(self, result: dict, cost: float = 0.01, model: str = "stub"):
        self.result = result
        self.cost = cost
        self.model = model


class _StubClient:
    """LLMClient stand-in recording generate_structured calls."""

    def __init__(self, payload: dict):
        self.payload = payload
        self.calls: list[dict] = []
        self.config = SimpleNamespace(
            config_for_model=lambda name: (_ for _ in ()).throw(ValueError()),
        )

    def generate_structured(self, prompt, schema, *, system_prompt="", **kw):
        self.calls.append({
            "prompt": prompt,
            "schema": schema,
            "system": system_prompt,
            "kwargs": kw,
        })
        return _StubResponse(dict(self.payload))


def _outcome(status: str, *, evidence_tool: str = "",
             hypothesis: str = "integer overflow in outlen") -> ReviewOutcome:
    return ReviewOutcome(
        file="src/a.c", function="f", status=status,
        body="claimed bug", hypothesis=hypothesis,
        evidence_tool=evidence_tool, model="model-a",
        review_result={"status": status},
        line=1,
    )


def _config(tmp_path: Path, client, **kw) -> OrchestratorConfig:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(
        target_path=target, out_dir=out,
        adversarial=True, llm_client=client, **kw,
    )


def _result(*outcomes: ReviewOutcome) -> OrchestratorResult:
    result = OrchestratorResult(outcomes=list(outcomes))
    result.findings = sum(1 for o in outcomes if o.status == "finding")
    result.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
    result.clean = sum(1 for o in outcomes if o.status == "clean")
    return result


# ---------------------------------------------------------------------------
# Prompt + parsing
# ---------------------------------------------------------------------------

class TestPromptConstruction:
    def test_prompt_is_enveloped(self):
        user, system = build_refutation_prompt(
            "src/a.c", "f",
            "integer overflow in outlen",
            "prior detail", "int f(void) { return 0; }",
        )
        assert "ATTACK this specific hypothesis" in system
        # untrusted content lands in the user message, not the system
        assert "integer overflow in outlen" not in system
        assert "integer overflow in outlen" in user
        # hypothesis / detail / source arrive as nonce-tagged
        # untrusted envelope blocks, not raw interpolation
        assert 'kind="finding-hypothesis"' in user
        assert 'kind="finding-detail"' in user
        assert 'kind="source-code"' in user
        assert '<slot name="function" trust="untrusted">' in user

    def test_prompt_carries_source_block(self):
        user, _ = build_refutation_prompt(
            "src/a.c", "f", "h", "b", "unique_source_marker_123",
        )
        assert "unique_source_marker_123" in user


class TestParseRefutation:
    def test_valid_verdicts(self):
        for verdict in (VERDICT_REFUTED, VERDICT_STANDS,
                        VERDICT_NEEDS_EVIDENCE):
            parsed = parse_refutation({
                "verdict": verdict, "counter_argument": "because",
            })
            assert parsed is not None
            assert parsed.verdict == verdict

    def test_unknown_verdict_rejected(self):
        assert parse_refutation({"verdict": "maybe",
                                 "counter_argument": "x"}) is None

    def test_refuted_without_argument_rejected(self):
        """A refutation with no argument and no named mechanism must
        never demote anything."""
        assert parse_refutation({"verdict": "refuted",
                                 "counter_argument": ""}) is None

    def test_non_dict_rejected(self):
        assert parse_refutation("refuted") is None
        assert parse_refutation(None) is None


class TestPickRefuterModel:
    def test_single_model_self_adversarial(self):
        assert pick_refuter_model(["model-a"], "model-a") == "model-a"

    def test_multi_model_prefers_different_model(self):
        assert pick_refuter_model(
            ["model-a", "model-b"], "model-a",
        ) == "model-b"

    def test_default_returns_none(self):
        assert pick_refuter_model(["default"], "") is None


class TestRunRefutation:
    def test_stub_call_roundtrip(self):
        client = _StubClient({
            "verdict": "refuted",
            "counter_argument": "guard at line 2 dominates",
            "defeating_mechanism": "len check at line 2",
            "settling_evidence": "",
        })
        ref = run_refutation(
            client, file="a.c", function="f",
            hypothesis="h", body="b", source="s",
        )
        assert ref is not None
        assert ref.verdict == VERDICT_REFUTED
        assert ref.defeating_mechanism == "len check at line 2"
        assert len(client.calls) == 1
        assert client.calls[0]["schema"]["properties"]["verdict"]["enum"]

    def test_call_failure_returns_none(self):
        class _Boom:
            config = SimpleNamespace()

            def generate_structured(self, *a, **kw):
                raise RuntimeError("provider down")

        assert run_refutation(
            _Boom(), file="a.c", function="f",
            hypothesis="h", body="b", source="s",
        ) is None


# ---------------------------------------------------------------------------
# Post-loop pass — verdict routing
# ---------------------------------------------------------------------------

class TestAdversarialRefutePass:
    def test_stands_keeps_status_and_annotates(self, tmp_path):
        client = _StubClient({
            "verdict": "stands",
            "counter_argument": "no guard defeats it",
        })
        outcome = _outcome("finding")
        result = _result(outcome)
        _adversarial_refute_pass(result, _config(tmp_path, client))
        assert result.outcomes[0].status == "finding"
        assert result.adversarial_stands == 1
        note = result.outcomes[0].review_result["adversarial_review"]
        assert note["verdict"] == "stands"

    def test_textual_objection_preserves_finding(self, tmp_path):
        client = _StubClient({
            "verdict": "refuted",
            "counter_argument": "the caller contract rules it out",
            "defeating_mechanism": "callers always pass len <= 16",
        })
        outcome = _outcome("finding")
        result = _result(outcome)
        _adversarial_refute_pass(result, _config(tmp_path, client))
        assert result.outcomes[0].status == "finding"
        assert result.findings == 1
        assert result.suspicious == 0
        assert result.adversarial_refuted == 0
        assert result.outcomes[0].review_result["adversarial_review"]["adjudication"] == "unverified"

    def test_textual_objection_cannot_clear_suspicious(self, tmp_path):
        client = _StubClient({
            "verdict": "refuted",
            "counter_argument": "bounds check at line 3",
            "defeating_mechanism": "bounds check at line 3",
        })
        outcome = _outcome("suspicious")
        result = _result(outcome)
        _adversarial_refute_pass(result, _config(tmp_path, client))
        assert result.outcomes[0].status == "suspicious"
        assert result.clean == 0
        assert result.suspicious == 1
        assert result.adversarial_refuted == 0
        assert result.outcomes[0].review_result["adversarial_review"]["proposed_refutation"] is True

    def test_tool_backed_suspicious_never_drops_below_suspicious(
        self, tmp_path,
    ):
        client = _StubClient({
            "verdict": "refuted",
            "counter_argument": "the guard covers this",
            "defeating_mechanism": "guard",
        })
        outcome = _outcome("suspicious", evidence_tool="smt:check-overflow")
        result = _result(outcome)
        _adversarial_refute_pass(result, _config(tmp_path, client))
        assert result.outcomes[0].status == "suspicious"
        assert result.suspicious == 1
        assert result.outcomes[0].body == "claimed bug"
        assert result.outcomes[0].evidence_tool == "smt:check-overflow"

    def test_needs_evidence_routes_to_dark(self, tmp_path):
        client = _StubClient({
            "verdict": "needs_evidence",
            "counter_argument": "depends on unseen callers",
            "settling_evidence": "check whether any caller passes "
                                 "attacker-controlled size",
        })
        outcome = _outcome("suspicious")
        result = _result(outcome)
        _adversarial_refute_pass(result, _config(tmp_path, client))
        assert result.outcomes[0].status == "suspicious"  # no demotion
        rr = result.outcomes[0].review_result
        assert rr["adversarial_needs_evidence"] is True

    @pytest.mark.parametrize("status", ["finding", "suspicious"])
    def test_named_check_remains_a_proposal_without_dispatch(
        self, tmp_path, monkeypatch, status,
    ):
        import core.audit.orchestrator as orch
        from core.audit.record import load_audit_log

        def unexpected(*args, **kwargs):
            pytest.fail("A critic must not rerun the original hypothesis as proof of its objection")

        monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", unexpected)
        monkeypatch.setattr(orch, "_run_tool_chain", unexpected)
        client = _StubClient({
            "verdict": "refuted",
            "counter_argument": "an unseen caller bounds the value",
            "settling_evidence": "check the caller guarantee",
        })
        outcome = _outcome(status)
        outcome.hypotheses = [
            {"mechanism": outcome.hypothesis}, {"mechanism": "independent concern"},
        ]
        result = _result(outcome)
        config = _config(tmp_path, client)
        _adversarial_refute_pass(result, config)
        assert result.outcomes[0] is outcome
        assert outcome.status == status
        assert len(outcome.hypotheses) == 2
        assert outcome.evidence_tool == ""
        assert result.adversarial_refuted == 0
        assert result.tier_counters["adversarial_refute"].inconclusive == 1
        assert result.cost_tracker.phases["adversarial"].calls == 1
        entries = load_audit_log(config.out_dir)
        entry = next(e for e in entries if e["action"] == "adversarial_refutation")
        assert entry["verdict"] == "refuted"  # proposed model judgment
        assert entry["adjudication"] == "unverified"
        assert entry["status"] == entry["prior_status"] == status
        assert entry["critique"]["counter_argument"] == "an unseen caller bounds the value"
        assert entry["critique"]["settling_evidence"] == "check the caller guarantee"
        assert entry["critique"]["hypothesis"] == outcome.hypothesis
        assert entry["critique"]["refuted"] is False

    def test_failed_refuter_is_noop(self, tmp_path):
        class _Boom:
            config = SimpleNamespace()

            def generate_structured(self, *a, **kw):
                raise RuntimeError("blocked")

        outcome = _outcome("finding")
        result = _result(outcome)
        _adversarial_refute_pass(result, _config(tmp_path, _Boom()))
        assert result.outcomes[0].status == "finding"
        assert result.adversarial_refuted == 0

    def test_clean_outcomes_not_attacked(self, tmp_path):
        client = _StubClient({
            "verdict": "refuted", "counter_argument": "x",
            "defeating_mechanism": "y",
        })
        outcome = _outcome("clean")
        outcome.status = "clean"
        result = _result(outcome)
        _adversarial_refute_pass(result, _config(tmp_path, client))
        assert not client.calls

    def test_audit_log_records_verdicts(self, tmp_path):
        client = _StubClient({
            "verdict": "stands", "counter_argument": "solid",
        })
        outcome = _outcome("finding")
        result = _result(outcome)
        config = _config(tmp_path, client)
        _adversarial_refute_pass(result, config)
        log = (config.out_dir / ".audit-log.jsonl").read_text()
        assert "adversarial_refutation" in log


# ---------------------------------------------------------------------------
# Dark-pass eligibility for needs_evidence
# ---------------------------------------------------------------------------

class TestDarkEligibility:
    def test_needs_evidence_outcome_reaches_dark_pass(
        self, tmp_path, monkeypatch,
    ):
        witnessed: list[str] = []

        def fake_llm(prompt, system):
            witnessed.append(prompt)
            raise RuntimeError("stop after prompt build")

        outcome = ReviewOutcome(
            file="src/a.py", function="f", status="suspicious",
            body="b", hypothesis="h",
            review_result={"adversarial_needs_evidence": True},
        )
        result = _result(outcome)
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        _run_dark_verification(result, config, llm_client=fake_llm, include_diagnostics=True)
        assert witnessed, (
            "adversarial_needs_evidence outcomes must be dark-eligible"
        )


# ---------------------------------------------------------------------------
# In-loop multi-model refute_fn
# ---------------------------------------------------------------------------

class TestMultiModelRefutation:
    def test_model_objection_preserves_panel_item(self, tmp_path):
        client = _StubClient({
            "verdict": "refuted",
            "counter_argument": "guard dominates",
            "defeating_mechanism": "guard at line 4",
        })
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            models=["model-a", "model-b"], multi_model=True,
            adversarial=True, llm_client=client,
        )

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="f", status="finding",
                body="bug", hypothesis="overflow",
            )

        ctx = {"file": "a.c", "function": "f", "line_start": 1,
               "source": "int f() {}"}
        outcome = _multi_pass_review(review_fn, ctx, config, passes=1)
        # Consensus and a critic's disagreement remain model judgments.
        assert outcome.status == "finding"
        assert client.calls, "refuter must actually be called"
        rr = outcome.review_result or {}
        note = rr["adversarial_review"]
        assert note["verdict"] == "refuted"
        assert note["adjudication"] == "unverified"
        assert note["refuted"] is False
        assert note["proposed_refutation"] is True

    def test_needs_evidence_marks_dark_routing(self, tmp_path):
        client = _StubClient({
            "verdict": "needs_evidence",
            "counter_argument": "cannot settle statically",
            "settling_evidence": "run the function with size=2**32",
        })
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            models=["model-a", "model-b"], multi_model=True,
            adversarial=True, llm_client=client,
        )

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="f", status="finding",
                body="bug", hypothesis="overflow",
            )

        ctx = {"file": "a.c", "function": "f", "line_start": 1,
               "source": "int f() {}"}
        outcome = _multi_pass_review(review_fn, ctx, config, passes=1)
        assert outcome.status == "finding"  # not demoted
        rr = outcome.review_result or {}
        assert rr.get("adversarial_needs_evidence") is True

    def test_stands_verdict_keeps_finding(self, tmp_path):
        client = _StubClient({
            "verdict": "stands",
            "counter_argument": "could not defeat it",
        })
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            models=["model-a", "model-b"], multi_model=True,
            adversarial=True, llm_client=client,
        )

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="f", status="finding",
                body="bug", hypothesis="overflow",
            )

        ctx = {"file": "a.c", "function": "f", "line_start": 1,
               "source": "int f() {}"}
        outcome = _multi_pass_review(review_fn, ctx, config, passes=1)
        assert outcome.status == "finding"
