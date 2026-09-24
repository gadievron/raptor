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
