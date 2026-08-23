"""Audit-purpose framing coverage across auxiliary LLM call classes (A1).

The final comparison audit lost the ``summary`` (18/18) and
``spec_inference`` (19/19) call classes to provider content-policy
refusals while every ``review`` call succeeded — the refused classes
presented bare code plus a security-extraction ask with no audit
context. These tests pin, per call class, that the constructed system
prompt carries :data:`core.security.prompt_framing.
SECURITY_AUDIT_FRAMING`. Prompt construction only — no live calls.
"""

from __future__ import annotations

from types import SimpleNamespace

from core.security.prompt_framing import (
    SECURITY_AUDIT_FRAMING,
    with_audit_framing,
)


class TestWithAuditFraming:
    def test_prepends(self):
        out = with_audit_framing("You are X.")
        assert out.startswith(SECURITY_AUDIT_FRAMING)
        assert out.endswith("You are X.")

    def test_idempotent(self):
        once = with_audit_framing("You are X.")
        assert with_audit_framing(once) == once

    def test_framing_is_static_defensive_context(self):
        # The framing must state authorization and defensive purpose,
        # and must never carry interpolation placeholders.
        assert "authorized" in SECURITY_AUDIT_FRAMING
        assert "audit" in SECURITY_AUDIT_FRAMING
        assert "{" not in SECURITY_AUDIT_FRAMING
        assert "%s" not in SECURITY_AUDIT_FRAMING


class TestSummaryClass:
    def test_summary_system_prompt_carries_framing(self):
        from core.audit.llm_summaries import build_summary_prompt

        _user, system = build_summary_prompt("a.c", "f", "int f(void){}")
        assert SECURITY_AUDIT_FRAMING in system


class TestSpecInferenceClass:
    def test_spec_system_prompt_carries_framing(self):
        from core.audit.spec_inference import build_spec_prompt

        _user, system = build_spec_prompt("f", "a.c", "int f(void){}")
        assert SECURITY_AUDIT_FRAMING in system


class TestGlanceBatchClass:
    def test_batch_system_prompt_carries_framing(self):
        from core.audit.batch_glance import format_batch_prompt

        ctxs = [{
            "file": "a.c", "function": "f", "source": "int f(void){}",
            "line_start": 1, "line_end": 1,
        }]
        _user, system = format_batch_prompt(ctxs)
        assert SECURITY_AUDIT_FRAMING in system


class TestRuleRefinementClass:
    def test_rule_refinement_system_prompt_carries_framing(self):
        from core.audit.llm_review import call_llm_for_rule_refinement

        captured = {}

        class _Client:
            def generate(self, prompt, *, system_prompt, **kwargs):
                captured["system"] = system_prompt
                return SimpleNamespace(text="rules: []")

        call_llm_for_rule_refinement(
            "refine this", SimpleNamespace(), client=_Client(),
        )
        assert SECURITY_AUDIT_FRAMING in captured["system"]


class TestSecurityClassifierClass:
    def test_classification_system_prompt_carries_framing(self):
        from core.audit.security_classifier import (
            _build_classification_prompt,
        )

        outcome = SimpleNamespace(
            file="a.c", function="f", status="suspicious",
            hypothesis="h", body="b",
            review_result={"bug_class": "bounds", "cwe": "CWE-120"},
        )
        _user, system = _build_classification_prompt(outcome, "")
        assert SECURITY_AUDIT_FRAMING in system


class TestChainDetectorClass:
    def test_chain_system_prompt_carries_framing(self):
        from core.audit.chain_detector import _build_chain_prompt

        a = SimpleNamespace(
            file="a.c", function="f", hypothesis="h1", body="b1",
            review_result={"bug_class": "bounds"},
        )
        b = SimpleNamespace(
            file="b.c", function="g", hypothesis="h2", body="b2",
            review_result={"bug_class": "bounds"},
        )
        _user, system = _build_chain_prompt(a, b)
        assert SECURITY_AUDIT_FRAMING in system


class TestAdversarialRefuteClass:
    def test_refutation_system_prompt_carries_framing(self):
        from core.audit.adversarial_refute import build_refutation_prompt

        _user, system = build_refutation_prompt(
            "a.c", "f", "hypothesis", "body", "int f(void){}",
        )
        assert SECURITY_AUDIT_FRAMING in system


class TestDarkVerifyClass:
    def test_witness_system_prompt_carries_framing_per_language(self):
        from core.audit.dark_verify import build_witness_prompt

        for file in ("a.py", "a.c", "a.go", "a.js", "a.rs"):
            _user, system = build_witness_prompt(
                file, "f", "hypothesis", "body",
            )
            assert SECURITY_AUDIT_FRAMING in system, file


class TestCheckerSynthesisClass:
    def test_synthesis_call_wrapper_frames_system_prompt(self):
        from core.audit.checker_synthesis import _build_llm_callable

        captured = {}

        class _Client:
            total_cost = 0.0

            def generate_structured(self, *, prompt, schema, system_prompt,
                                    **kwargs):
                captured["system"] = system_prompt
                return {}, None

        config = SimpleNamespace(llm_budget_client=_Client(), models=None)
        built = _build_llm_callable(config)
        assert built is not None
        call, _client = built
        call("p", {"type": "object"}, "You are a rule author.")
        assert SECURITY_AUDIT_FRAMING in captured["system"]


class TestAgreementGateClass:
    def test_gate_system_prompt_carries_framing(self):
        from core.concepts.answer_gate import _GATE_SYSTEM_PROMPT

        assert _GATE_SYSTEM_PROMPT.startswith(SECURITY_AUDIT_FRAMING)


class TestReviewClassAlreadyFramed:
    """The review class succeeded 36/36 — its native methodology prompt
    IS the framing (auditor role + audit workflow). Pin the property
    that motivated the framing text so a refactor cannot silently drop
    it."""

    def test_review_system_prompt_states_auditor_role(self):
        from core.audit.llm_review import _DEFAULT_SYSTEM_PROMPT

        assert "security auditor reviewing code" in _DEFAULT_SYSTEM_PROMPT
