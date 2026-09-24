"""Tests for the LLM account-contention posture: the tuning.json
reader and the posture-aware auto worker ceilings in
``derive_max_workers`` (all tuning reads stubbed — no file, no
network).
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("RAPTOR_BEDROCK_MAX_WORKERS", raising=False)
    monkeypatch.delenv("RAPTOR_CC_MAX_WORKERS", raising=False)
    import core.llm.concurrency as conc
    monkeypatch.setattr(conc, "read_tuning_max_llm_workers", lambda: None)
    # Warning memo is per-process — reset for test isolation.
    monkeypatch.setattr(conc, "_posture_warning_emitted", False)


def _set_tuning(monkeypatch, data: dict):
    import core.llm.concurrency as conc
    monkeypatch.setattr(conc, "_read_tuning", lambda: data)


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

class TestPostureReader:

    def test_absent_reads_shared(self, monkeypatch):
        import core.llm.concurrency as conc
        _set_tuning(monkeypatch, {})
        assert conc.read_tuning_llm_account_posture() == "shared"

    def test_solo_reads_solo(self, monkeypatch):
        import core.llm.concurrency as conc
        _set_tuning(monkeypatch, {"llm_account_posture": "solo"})
        assert conc.read_tuning_llm_account_posture() == "solo"

    def test_shared_reads_shared(self, monkeypatch):
        import core.llm.concurrency as conc
        _set_tuning(monkeypatch, {"llm_account_posture": "shared"})
        assert conc.read_tuning_llm_account_posture() == "shared"

    def test_unrecognised_warns_once_and_reads_shared(self, monkeypatch,
                                                      caplog):
        import core.llm.concurrency as conc
        _set_tuning(monkeypatch, {"llm_account_posture": "SOLO"})
        with caplog.at_level("WARNING", logger="core.llm.concurrency"):
            assert conc.read_tuning_llm_account_posture() == "shared"
            # Fan-out loops re-read per batch — the warning is
            # once-per-process, not once-per-call.
            assert conc.read_tuning_llm_account_posture() == "shared"
        warnings = [r for r in caplog.records
                    if "llm_account_posture" in r.getMessage()]
        assert len(warnings) == 1

    def test_non_string_reads_shared(self, monkeypatch):
        import core.llm.concurrency as conc
        _set_tuning(monkeypatch, {"llm_account_posture": 3})
        assert conc.read_tuning_llm_account_posture() == "shared"


# ---------------------------------------------------------------------------
# Posture → ceiling derivation
# ---------------------------------------------------------------------------

def _primary(monkeypatch, provider: str, model: str, **kw):
    from core.llm.config import ModelConfig
    mc = ModelConfig(provider=provider, model_name=model, **kw)
    monkeypatch.setattr(
        "core.llm.config._get_default_primary_model",
        lambda prefer=None: mc,
    )


class TestPostureCeilings:

    MODEL = "anthropic.claude-sonnet-5"

    def _derive(self, monkeypatch, posture: str) -> int:
        import core.llm.concurrency as conc
        _primary(monkeypatch, "bedrock", self.MODEL)
        _set_tuning(monkeypatch, {"llm_account_posture": posture})
        return conc.derive_max_workers(self.MODEL)

    def test_shared_holds_fair_share(self, monkeypatch):
        import core.llm.concurrency as conc
        assert (self._derive(monkeypatch, "shared")
                == conc.BEDROCK_MAX_WORKERS_DEFAULT)

    def test_absent_posture_holds_fair_share(self, monkeypatch):
        import core.llm.concurrency as conc
        _primary(monkeypatch, "bedrock", self.MODEL)
        _set_tuning(monkeypatch, {})
        assert (conc.derive_max_workers(self.MODEL)
                == conc.BEDROCK_MAX_WORKERS_DEFAULT)

    def test_solo_uses_solo_ceiling(self, monkeypatch):
        import core.llm.concurrency as conc
        assert (self._derive(monkeypatch, "solo")
                == conc.BEDROCK_MAX_WORKERS_SOLO)

    def test_env_override_beats_posture_both_directions(self, monkeypatch):
        import core.llm.concurrency as conc
        monkeypatch.setenv("RAPTOR_BEDROCK_MAX_WORKERS", "2")
        assert self._derive(monkeypatch, "solo") == 2
        monkeypatch.setenv("RAPTOR_BEDROCK_MAX_WORKERS", "20")
        _primary(monkeypatch, "bedrock", self.MODEL)
        _set_tuning(monkeypatch, {"llm_account_posture": "shared"})
        assert conc.derive_max_workers(self.MODEL) == 20

    def test_tuning_max_llm_workers_beats_posture(self, monkeypatch):
        import core.llm.concurrency as conc
        _primary(monkeypatch, "bedrock", self.MODEL)
        _set_tuning(monkeypatch, {"llm_account_posture": "shared"})
        monkeypatch.setattr(conc, "read_tuning_max_llm_workers",
                            lambda: 24)
        assert conc.derive_max_workers(self.MODEL) == 24

    def test_claudecode_cap_not_posture_routed(self, monkeypatch):
        # The cc ceiling bounds subprocess RSS + the prompt-cache
        # write race — costs a solo account pays exactly like a
        # shared one — so solo must not raise it.
        import core.llm.concurrency as conc
        _primary(monkeypatch, "claudecode", "backend.resolved-id")
        _set_tuning(monkeypatch, {"llm_account_posture": "solo"})
        assert (conc.derive_max_workers("backend.resolved-id")
                == conc.CC_MAX_WORKERS_DEFAULT)

    def test_ceiling_constants_pinned(self):
        # Mutation pins: the shared value is the production fair-share
        # default (raising it silently taxes every co-tenant of the
        # account); the solo value sits strictly between fair-share
        # and the 429-storm-observed 32-worker cap.
        import core.llm.concurrency as conc
        assert conc.BEDROCK_MAX_WORKERS_DEFAULT == 8
        assert conc.BEDROCK_MAX_WORKERS_SOLO == 16
        assert (conc.BEDROCK_MAX_WORKERS_DEFAULT
                < conc.BEDROCK_MAX_WORKERS_SOLO
                < conc.MAX_WORKERS_CAP)


class TestExplicitMaxWorkersSupremacy:

    def test_audit_flag_bypasses_derivation(self, monkeypatch):
        # Operator ownership: --max-workers never consults posture,
        # transport caps, or the sibling heuristic.
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _resolve_max_workers,
        )

        def _boom(model):  # pragma: no cover - must never run
            raise AssertionError("derivation consulted despite flag")

        monkeypatch.setattr(
            "core.llm.concurrency.derive_max_workers", _boom)
        from pathlib import Path
        config = OrchestratorConfig(
            target_path=Path("."), out_dir=Path("."), max_workers=5)
        assert _resolve_max_workers(config) == 5
