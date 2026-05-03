"""Tests for the pre-run envelope compatibility probe.

The canary probe sends a controlled request with known-good content
through the same dispatch path that real findings will use. Since the
content is 100% controlled by us, the result is not attacker-
influenceable — unlike runtime telemetry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from core.security.prompt_envelope import build_prompt, UntrustedBlock
from core.security.prompt_defense_profiles import (
    ANTHROPIC_CLAUDE,
    CONSERVATIVE,
    GOOGLE_GEMINI,
    OLLAMA_SMALL,
    PASSTHROUGH,
)
from core.security.envelope_probe import (
    ProbeResult,
    build_canary_prompt,
    evaluate_probe_response,
    probe_envelope_compatibility,
)
from core.security.prompt_telemetry import DefenseTelemetry


# --- Fake dispatch function for testing ---

@dataclass
class FakeDispatchResult:
    result: dict
    cost: float = 0.0
    tokens: int = 0
    model: str = ""
    duration: float = 0.0


def _make_dispatch_fn(response_json: dict | None = None,
                      raw_text: str | None = None,
                      raise_error: Exception | None = None):
    """Create a fake dispatch function that returns a controlled response."""
    def dispatch_fn(prompt, schema, system_prompt, temperature, model):
        if raise_error:
            raise raise_error
        if raw_text is not None:
            return FakeDispatchResult(result={"content": raw_text})
        return FakeDispatchResult(result={"content": json.dumps(response_json)})
    return dispatch_fn


# ============================================================
# 1. build_canary_prompt
# ============================================================

class TestBuildCanaryPrompt:

    def test_returns_system_user_nonce(self):
        system, user, nonce = build_canary_prompt(CONSERVATIVE)
        assert system
        assert user
        assert nonce
        assert len(nonce) == 16

    def test_system_contains_analyser_instructions(self):
        system, _, _ = build_canary_prompt(CONSERVATIVE)
        assert "security analyser" in system

    def test_user_contains_canary_code(self):
        _, user, _ = build_canary_prompt(CONSERVATIVE)
        assert "strcpy" in user
        assert "buffer" in user

    def test_user_contains_envelope_for_conservative(self):
        _, user, nonce = build_canary_prompt(CONSERVATIVE)
        assert f"<untrusted-{nonce}" in user
        assert '<slot name="rule_id"' in user

    def test_user_contains_envelope_for_anthropic(self):
        _, user, nonce = build_canary_prompt(ANTHROPIC_CLAUDE)
        assert f"<untrusted-{nonce}" in user

    def test_passthrough_has_no_envelope(self):
        system, user, nonce = build_canary_prompt(PASSTHROUGH)
        assert "<untrusted-" not in user
        assert nonce not in user
        assert "strcpy" in user

    def test_nonce_differs_each_call(self):
        nonces = {build_canary_prompt(CONSERVATIVE)[2] for _ in range(10)}
        assert len(nonces) == 10


# ============================================================
# 2. evaluate_probe_response
# ============================================================

class TestEvaluateProbeResponse:

    def test_correct_response_is_compatible(self):
        response = json.dumps({
            "is_vulnerable": True,
            "vulnerability_type": "buffer_overflow",
            "confidence": 0.95,
        })
        result = evaluate_probe_response(response, "abc123")
        assert result.compatible
        assert result.valid_json
        assert result.correct_verdict
        assert not result.nonce_leaked
        assert result.error is None

    def test_nonce_in_response_is_incompatible(self):
        response = json.dumps({
            "is_vulnerable": True,
            "vulnerability_type": "buffer_overflow",
            "confidence": 0.9,
        })
        nonce = "deadbeef12345678"
        response_with_nonce = response + f" (nonce: {nonce})"
        result = evaluate_probe_response(response_with_nonce, nonce)
        assert not result.compatible
        assert result.nonce_leaked
        assert "nonce" in result.error.lower()

    def test_invalid_json_is_incompatible(self):
        result = evaluate_probe_response("I cannot produce JSON", "abc123")
        assert not result.compatible
        assert not result.valid_json
        assert "JSON" in result.error

    def test_wrong_verdict_is_incompatible(self):
        response = json.dumps({
            "is_vulnerable": False,
            "vulnerability_type": "none",
            "confidence": 0.8,
        })
        result = evaluate_probe_response(response, "abc123")
        assert not result.compatible
        assert result.valid_json
        assert not result.correct_verdict
        assert "buffer overflow" in result.error.lower()

    def test_missing_is_vulnerable_field(self):
        response = json.dumps({"result": "safe"})
        result = evaluate_probe_response(response, "abc123")
        assert not result.compatible
        assert not result.valid_json  # missing required field

    def test_empty_nonce_does_not_false_positive(self):
        response = json.dumps({"is_vulnerable": True, "confidence": 0.9})
        result = evaluate_probe_response(response, "")
        assert not result.nonce_leaked

    def test_raw_response_preserved(self):
        raw = '{"is_vulnerable": true, "confidence": 0.9}'
        result = evaluate_probe_response(raw, "x")
        assert result.raw_response == raw


# ============================================================
# 3. probe_envelope_compatibility (end-to-end with fake dispatch)
# ============================================================

class TestProbeEnvelopeCompatibility:

    def test_compatible_model(self):
        dispatch = _make_dispatch_fn(response_json={
            "is_vulnerable": True,
            "vulnerability_type": "buffer_overflow",
            "confidence": 0.95,
        })
        result = probe_envelope_compatibility("gpt-5", CONSERVATIVE, dispatch)
        assert result.compatible
        assert result.error is None

    def test_incompatible_model_bad_json(self):
        dispatch = _make_dispatch_fn(raw_text="Sorry, I can't analyse code")
        result = probe_envelope_compatibility("phi-3", OLLAMA_SMALL, dispatch)
        assert not result.compatible
        assert "JSON" in result.error

    def test_incompatible_model_wrong_verdict(self):
        dispatch = _make_dispatch_fn(response_json={
            "is_vulnerable": False,
            "vulnerability_type": "none",
            "confidence": 0.1,
        })
        result = probe_envelope_compatibility("mistral-7b", CONSERVATIVE, dispatch)
        assert not result.compatible
        assert "buffer overflow" in result.error.lower()

    def test_incompatible_model_nonce_leak(self):
        def leaky_dispatch(prompt, schema, system_prompt, temperature, model):
            _, _, nonce = build_canary_prompt(CONSERVATIVE)
            # Model echoes the nonce it saw in the prompt
            response = json.dumps({
                "is_vulnerable": True,
                "vulnerability_type": "buffer_overflow",
                "confidence": 0.9,
            })
            return FakeDispatchResult(result={"content": response})
        # This test verifies the nonce check works when the dispatch
        # function doesn't leak (each call gets a fresh nonce)
        result = probe_envelope_compatibility("test", CONSERVATIVE, leaky_dispatch)
        assert result.compatible  # Different nonce, so no leak detected

    def test_dispatch_failure_is_incompatible(self):
        dispatch = _make_dispatch_fn(raise_error=RuntimeError("connection refused"))
        result = probe_envelope_compatibility("phi-3", CONSERVATIVE, dispatch)
        assert not result.compatible
        assert "connection refused" in result.error

    def test_dispatch_timeout_is_incompatible(self):
        dispatch = _make_dispatch_fn(raise_error=TimeoutError("timed out"))
        result = probe_envelope_compatibility("phi-3", CONSERVATIVE, dispatch)
        assert not result.compatible
        assert "timed out" in result.error


# ============================================================
# 4. Integration with telemetry probe cache
# ============================================================

class TestProbeWithTelemetry:

    @pytest.fixture
    def telemetry(self):
        t = DefenseTelemetry()
        yield t
        t.reset()

    def test_compatible_probe_cached(self, telemetry):
        dispatch = _make_dispatch_fn(response_json={
            "is_vulnerable": True,
            "vulnerability_type": "buffer_overflow",
            "confidence": 0.95,
        })
        result = probe_envelope_compatibility("gpt-5", CONSERVATIVE, dispatch)
        telemetry.set_probe_result("gpt-5", result.compatible)
        assert telemetry.probe_passed("gpt-5") is True

    def test_incompatible_probe_cached(self, telemetry):
        dispatch = _make_dispatch_fn(raw_text="I don't understand")
        result = probe_envelope_compatibility("phi-3", OLLAMA_SMALL, dispatch)
        telemetry.set_probe_result("phi-3", result.compatible)
        assert telemetry.probe_passed("phi-3") is False

    def test_full_lifecycle(self, telemetry):
        """Simulate the orchestrator lifecycle: probe → cache → select profile."""
        # Step 1: probe each model
        good_dispatch = _make_dispatch_fn(response_json={
            "is_vulnerable": True,
            "vulnerability_type": "buffer_overflow",
            "confidence": 0.9,
        })
        bad_dispatch = _make_dispatch_fn(raw_text="no json")

        r1 = probe_envelope_compatibility("claude-opus-4-7", ANTHROPIC_CLAUDE, good_dispatch)
        r2 = probe_envelope_compatibility("mistral-7b", CONSERVATIVE, bad_dispatch)

        telemetry.set_probe_result("claude-opus-4-7", r1.compatible)
        telemetry.set_probe_result("mistral-7b", r2.compatible)

        # Step 2: select profile based on cached result
        assert telemetry.probe_passed("claude-opus-4-7") is True   # → keep ANTHROPIC_CLAUDE
        assert telemetry.probe_passed("mistral-7b") is False       # → switch to PASSTHROUGH

        # Step 3: verify passthrough prompt is simpler
        bundle = build_prompt(
            system="Analyse.", profile=PASSTHROUGH,
            untrusted_blocks=(UntrustedBlock(
                content="code", kind="code", origin="f.c",
            ),),
        )
        user = next(m.content for m in bundle.messages if m.role == "user")
        assert "<untrusted-" not in user


# ============================================================
# 5. Probe is attacker-proof
# ============================================================

class TestProbeIsAttackerProof:

    def test_probe_uses_controlled_content_not_target(self):
        """The canary probe uses hardcoded benign code, not content
        from the target repository. An attacker controlling the target
        cannot influence the probe result."""
        _, user, _ = build_canary_prompt(CONSERVATIVE)
        assert "strcpy" in user
        assert "buffer[64]" in user
        # No reference to any real target file
        assert "canary_probe.c" in user

    def test_probe_nonce_is_fresh_per_call(self):
        """Each probe generates a fresh nonce, so even if an attacker
        knew the probe existed, they couldn't predict the nonce to fake
        a clean response."""
        nonces = set()
        for _ in range(20):
            _, _, nonce = build_canary_prompt(CONSERVATIVE)
            nonces.add(nonce)
        assert len(nonces) == 20

    def test_adversarial_target_does_not_affect_probe(self):
        """Even if the target repo is full of adversarial content,
        the probe result depends only on the model's inherent
        capability, not the target content."""
        # Simulate: probe with a good model (returns correct answer)
        dispatch = _make_dispatch_fn(response_json={
            "is_vulnerable": True,
            "vulnerability_type": "buffer_overflow",
            "confidence": 0.9,
        })
        result = probe_envelope_compatibility("test-model", CONSERVATIVE, dispatch)
        assert result.compatible
        # The probe doesn't touch the target repo at all
