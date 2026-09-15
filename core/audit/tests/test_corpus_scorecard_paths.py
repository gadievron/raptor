"""The corpus ground-truth writer resolves the sidecar through the
shared resolver — ``RAPTOR_SCORECARD_PATH`` isolates the ledger.

Pre-fix ``_record_scorecard`` hand-rolled the ``RAPTOR_DIR/out``
resolution, so an isolated run (tests, sandboxes) still wrote corpus
ground-truth events into the real install ledger — the exact drift the
shared resolver exists to prevent.
"""

from __future__ import annotations

import json
from typing import Any

import core.audit.corpus.run_corpus as rc


class TestCorpusScorecardOverride:
    def test_record_scorecard_writes_to_override(
        self, tmp_path, monkeypatch,
    ) -> None:
        install = tmp_path / "install"
        (install / "out").mkdir(parents=True)
        isolated = tmp_path / "isolated_scorecard.json"
        monkeypatch.setenv("RAPTOR_DIR", str(install))
        monkeypatch.setenv("RAPTOR_SCORECARD_PATH", str(isolated))

        results: list[dict[str, Any]] = [
            {
                "function_id": "src/parse.c:parse_header",
                "bug_class": "integer-overflow",
                "expected": "finding",
                "actual": "finding",
                "match": True,
            },
            {
                "function_id": "src/parse.c:parse_body",
                "bug_class": "integer-overflow",
                "expected": "finding",
                "actual": "clean",
                "match": False,
                "hypothesis": "bounds check dominates the addition",
            },
        ]
        rc._record_scorecard(results, "test-model")

        # The writer is best-effort (swallows exceptions), so assert
        # on the artifact: events landed in the isolated ledger only.
        assert isolated.exists()
        data = json.loads(isolated.read_text(encoding="utf-8"))
        assert "test-model" in data.get("models", {})
        assert not (install / "out" / "llm_scorecard.json").exists()
