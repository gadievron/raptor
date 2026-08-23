"""Web oracle outcomes → scorecard: self-labeling wiring."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from packages.web.scorecard_bridge import record_web_oracle_outcomes


def _hit(vuln_type: str, status: str | None, param: str = "q") -> dict:
    hit = {
        "vulnerability_type": vuln_type,
        "endpoint": "https://t.example/search",
        "parameter": param,
        "oracle_signal": f"{vuln_type}:marker",
    }
    if status is not None:
        hit["verification"] = {"status": status}
    return hit


class _FakeLlm:
    def __init__(self, scorecard):
        self.scorecard = scorecard
        self.config = SimpleNamespace(
            primary_model=SimpleNamespace(model_name="test-model"),
        )


class TestRecordWebOracleOutcomes(unittest.TestCase):
    def _scorecard(self, tmpdir: str):
        from core.llm.scorecard.scorecard import ModelScorecard

        return ModelScorecard(Path(tmpdir) / "scorecard.json")

    def test_verified_and_refuted_land_in_web_cells(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scorecard = self._scorecard(tmpdir)
            llm = _FakeLlm(scorecard)

            recorded = record_web_oracle_outcomes(llm, [
                _hit("sqli", "verified"),
                _hit("xss", "refuted", param="cb"),
                _hit("ssti", "inconclusive"),   # no signal
                _hit("command_injection", None),  # never verified
                _hit("ssrf", "verified"),       # no decision class mapped
            ])

            self.assertEqual(recorded, 2)
            data = json.loads((Path(tmpdir) / "scorecard.json").read_text())
            cells = data["models"]["test-model"]
            self.assertIn("web:response-diff-classification", cells)
            self.assertIn("web:xss-reflection-triage", cells)

    def test_duplicate_finding_ids_record_once(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            llm = _FakeLlm(self._scorecard(tmpdir))
            hits = [_hit("sqli", "verified"), _hit("sqli", "verified")]
            self.assertEqual(record_web_oracle_outcomes(llm, hits), 1)

    def test_no_llm_or_model_degrades_to_zero(self):
        self.assertEqual(
            record_web_oracle_outcomes(None, [_hit("sqli", "verified")]), 0,
        )
        llm = MagicMock()
        llm.scorecard = None
        self.assertEqual(
            record_web_oracle_outcomes(llm, [_hit("sqli", "verified")]), 0,
        )

    def test_scorecard_failure_never_raises(self):
        llm = MagicMock()
        llm.scorecard = MagicMock()
        llm.config = SimpleNamespace(primary_model=SimpleNamespace(
            model_name="test-model",
        ))
        llm.scorecard.claim_and_record_tool_evidence.side_effect = (
            RuntimeError("disk full")
        )
        self.assertEqual(
            record_web_oracle_outcomes(llm, [_hit("sqli", "verified")]), 0,
        )


if __name__ == "__main__":
    unittest.main()


class TestGroundTruthGranularity(unittest.TestCase):
    """Contradictory verdicts on distinct payloads must BOTH land, and
    a later scan of the same target must be able to record a flipped
    verdict — the idempotency key is per (run, payload), never
    forever-per-endpoint."""

    def _llm(self, tmpdir: str) -> _FakeLlm:
        from core.llm.scorecard.scorecard import ModelScorecard

        return _FakeLlm(ModelScorecard(Path(tmpdir) / "scorecard.json"))

    def test_contradictory_verdicts_on_distinct_payloads_both_record(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            llm = self._llm(tmpdir)
            verified = _hit("sqli", "verified")
            verified["payload"] = "' OR 1=1--"
            refuted = _hit("sqli", "refuted")
            refuted["payload"] = "'; SELECT pg_sleep(0)--"

            self.assertEqual(
                record_web_oracle_outcomes(
                    llm, [verified, refuted], run_id="run-a",
                ),
                2,
            )

    def test_rescan_can_record_a_flipped_verdict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            llm = self._llm(tmpdir)
            hit = _hit("sqli", "verified")
            hit["payload"] = "' OR 1=1--"
            self.assertEqual(
                record_web_oracle_outcomes(llm, [hit], run_id="run-a"), 1,
            )
            # Same run re-records nothing (in-run idempotency)…
            self.assertEqual(
                record_web_oracle_outcomes(llm, [hit], run_id="run-a"), 0,
            )
            # …but the fixed-site rescan with the flipped verdict lands.
            flipped = dict(hit)
            flipped["verification"] = {"status": "refuted"}
            self.assertEqual(
                record_web_oracle_outcomes(
                    llm, [flipped], run_id="run-b",
                ),
                1,
            )

    def test_specialized_generation_model_gets_the_credit(self):
        from types import SimpleNamespace as NS

        from packages.web.scorecard_bridge import _payload_model_name

        class _Config:
            primary_model = NS(model_name="primary-model")

            def get_model_for_task(self, task_type):
                return NS(model_name="codegen-model")

        llm = NS(config=_Config())
        self.assertEqual(_payload_model_name(llm), "codegen-model")
