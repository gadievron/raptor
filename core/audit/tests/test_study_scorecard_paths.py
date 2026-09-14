"""The study-scorecard writers resolve the sidecar through the shared
resolver — ``RAPTOR_SCORECARD_PATH`` isolates the ledger end-to-end.

Pre-fix both writers hand-rolled the ``RAPTOR_DIR/out`` resolution, so
an isolated run (tests, sandboxes) still wrote study events into the
real install ledger — polluting accumulated reliability history, the
exact drift the shared resolver exists to prevent.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import core.audit.orchestrator as _orch


def _read_sidecar(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class TestStudyScorecardOverride:
    def test_record_study_scorecard_writes_to_override(
        self, tmp_path, monkeypatch,
    ):
        install = tmp_path / "install"
        (install / "out").mkdir(parents=True)
        isolated = tmp_path / "isolated_scorecard.json"
        monkeypatch.setenv("RAPTOR_DIR", str(install))
        monkeypatch.setenv("RAPTOR_SCORECARD_PATH", str(isolated))

        _orch._record_study_scorecard("test-model", False, "disagreed")

        # The writer is best-effort (swallows exceptions), so assert
        # on the artifact: event landed in the isolated ledger only.
        assert isolated.exists()
        data = _read_sidecar(isolated)
        assert "test-model" in data.get("models", {})
        assert not (install / "out" / "llm_scorecard.json").exists()

    def test_record_study_flip_writes_to_override(
        self, tmp_path, monkeypatch,
    ):
        install = tmp_path / "install"
        (install / "out").mkdir(parents=True)
        isolated = tmp_path / "isolated_scorecard.json"
        monkeypatch.setenv("RAPTOR_DIR", str(install))
        monkeypatch.setenv("RAPTOR_SCORECARD_PATH", str(isolated))

        config = SimpleNamespace(models=["test-model"])
        outcome = SimpleNamespace(model="test-model")
        _orch._record_study_flip(config, outcome)

        assert isolated.exists()
        data = _read_sidecar(isolated)
        assert "test-model" in data.get("models", {})
        assert not (install / "out" / "llm_scorecard.json").exists()
