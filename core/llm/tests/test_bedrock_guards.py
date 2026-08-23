"""Tests for the Bedrock operational guards: the shared-quota worker
cap, the same-weights multi-model warning, and the entitlement
preflight's classification/caching behavior (probes stubbed — no
network, no spend).
"""

from __future__ import annotations

import json
import urllib.error

import pytest


# ---------------------------------------------------------------------------
# Worker cap
# ---------------------------------------------------------------------------

class TestBedrockWorkerCap:

    @pytest.fixture(autouse=True)
    def _clean(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_BEDROCK_MAX_WORKERS", raising=False)
        import core.llm.concurrency as conc
        monkeypatch.setattr(
            conc, "read_tuning_max_llm_workers", lambda: None,
        )

    def _bedrock_primary(self, monkeypatch, model="anthropic.claude-sonnet-5"):
        import core.llm.concurrency as conc
        from core.llm.config import ModelConfig
        mc = ModelConfig(provider="bedrock", model_name=model)
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: mc,
        )
        return conc

    def test_bedrock_primary_clamped(self, monkeypatch):
        """An RPM-rich Bedrock model is clamped to the shared-quota
        ceiling instead of rpm//2."""
        conc = self._bedrock_primary(monkeypatch)
        workers = conc.derive_max_workers("anthropic.claude-sonnet-5")
        assert workers == conc.BEDROCK_MAX_WORKERS_DEFAULT

    def test_env_override(self, monkeypatch):
        conc = self._bedrock_primary(monkeypatch)
        monkeypatch.setenv("RAPTOR_BEDROCK_MAX_WORKERS", "2")
        assert conc.derive_max_workers("anthropic.claude-sonnet-5") == 2

    def test_non_bedrock_primary_unclamped(self, monkeypatch):
        import core.llm.concurrency as conc
        from core.llm.config import ModelConfig
        mc = ModelConfig(provider="anthropic", model_name="claude-sonnet-5",
                         api_key="k")
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: mc,
        )
        workers = conc.derive_max_workers("claude-sonnet-5")
        assert workers > conc.BEDROCK_MAX_WORKERS_DEFAULT


# ---------------------------------------------------------------------------
# Same-weights panel warning
# ---------------------------------------------------------------------------

class TestSameWeightsWarning:

    def test_warns_on_same_underlying_model(self, caplog):
        from core.llm.multi_model.dispatch import _warn_same_weights
        with caplog.at_level("WARNING"):
            _warn_same_weights([
                "anthropic.claude-sonnet-5",
                "us.anthropic.claude-sonnet-5",
            ])
        assert any("same" in r.message and "underlying" in r.message
                   for r in caplog.records)

    def test_silent_on_distinct_models(self, caplog):
        from core.llm.multi_model.dispatch import _warn_same_weights
        with caplog.at_level("WARNING"):
            _warn_same_weights([
                "anthropic.claude-sonnet-5", "gemini-2.5-pro",
            ])
        assert not caplog.records


# ---------------------------------------------------------------------------
# Entitlement preflight
# ---------------------------------------------------------------------------

def _mc(model="anthropic.claude-sonnet-5", **kw):
    from core.llm.config import ModelConfig
    fields = {"provider": "bedrock", "model_name": model}
    fields.update(kw)
    return ModelConfig(**fields)


class TestPreflight:

    @pytest.fixture(autouse=True)
    def _cache(self, monkeypatch, tmp_path):
        import core.llm.bedrock_preflight as pf
        monkeypatch.setattr(
            pf, "_CACHE_PATH", tmp_path / "preflight.json",
        )
        self.pf = pf

    def _run(self, monkeypatch, outcome, models=None):
        """Drive preflight with a stubbed probe returning *outcome*."""
        pf = self.pf
        monkeypatch.setattr(
            pf, "_configured_bedrock_models", lambda: models or [_mc()],
        )
        calls = []

        def _fake_probe(creds, mc):
            calls.append(mc.model_name)
            return outcome
        monkeypatch.setattr(pf, "_probe_one", _fake_probe)
        from core.llm.dispatcher.auth import CredentialStore
        warnings = pf.preflight_configured_bedrock(CredentialStore())
        return warnings, calls

    def test_success_cached_no_reprobe(self, monkeypatch):
        warnings, calls = self._run(monkeypatch, None)
        assert warnings == [] and len(calls) == 1
        # Second pass: fresh cache entry short-circuits the probe.
        warnings2, calls2 = self._run(monkeypatch, None)
        assert warnings2 == [] and calls2 == []

    def test_denial_warns_and_is_not_cached(self, monkeypatch):
        msg = "access denied"
        warnings, calls = self._run(monkeypatch, msg)
        assert warnings == [msg]
        # Failure not cached: next run probes again.
        warnings2, calls2 = self._run(monkeypatch, msg)
        assert warnings2 == [msg] and len(calls2) == 1

    def test_transient_skip_is_silent(self, monkeypatch):
        warnings, calls = self._run(monkeypatch, "")
        assert warnings == [] and len(calls) == 1

    def test_probe_budget_bounded(self, monkeypatch):
        models = [_mc(model=f"anthropic.claude-m{i}") for i in range(10)]
        warnings, calls = self._run(monkeypatch, "", models=models)
        assert len(calls) == self.pf._MAX_PROBES


class TestPreflightClassification:

    def _classify(self, monkeypatch, code, body=b"{}"):
        import core.llm.bedrock_preflight as pf
        from core.llm.dispatcher.auth import CredentialStore, PreparedRequest
        prepared = PreparedRequest(
            method="POST", url="https://bedrock-stub.test/x",
            headers={}, body=b"{}",
        )
        monkeypatch.setattr(
            pf, "_probe_request", lambda creds, mc: prepared,
        )

        def _raise(*a, **kw):
            raise urllib.error.HTTPError(
                "https://bedrock-stub.test/x", code, "err", None,
                __import__("io").BytesIO(body),
            )
        monkeypatch.setattr(pf.urllib.request, "urlopen", _raise)
        return pf._probe_one(CredentialStore(), _mc())

    def test_403_is_entitlement_warning(self, monkeypatch):
        out = self._classify(monkeypatch, 403)
        assert out and "access denied" in out

    def test_parameter_400_counts_as_entitled(self, monkeypatch):
        """A 4xx that reached the model with valid auth (e.g. a
        deprecated parameter) proves entitlement — no warning."""
        out = self._classify(
            monkeypatch, 400,
            body=json.dumps({"error": {
                "message": "`temperature` is deprecated"}}).encode(),
        )
        assert out is None

    def test_5xx_is_transient(self, monkeypatch):
        assert self._classify(monkeypatch, 503) == ""
