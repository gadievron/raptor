"""RetryTask.finalize must re-adjudicate self-contradiction.

The annotation graft keeps the prior record's flags for audit
continuity, but the flag must describe the MERGED result: a retry
that returned an internally consistent, decisive analysis is no
longer contradictory (else the "Inconsistent (review needed)" bucket
inflates forever), while a retry that is still contradictory keeps
the flag with a refreshed contradiction list.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.tasks import RetryTask  # noqa: E402


def _prior_with_flag() -> dict:
    return {
        "f1": {
            "finding_id": "f1",
            "is_true_positive": True,
            "is_exploitable": True,
            "exploitability_score": 0.5,
            "reasoning": "original contradictory reasoning",
            "self_contradictory": True,
            "contradictions": [
                "ruling='false_positive' but is_exploitable=True",
            ],
        },
    }


class TestRetryClearsStaleFlag:

    def test_clean_decisive_retry_clears_flag(self):
        prior = _prior_with_flag()
        fresh = [{
            "finding_id": "f1",
            "is_true_positive": False,
            "is_exploitable": False,
            "exploitability_score": 0.05,
            "ruling": "false_positive",
            "reasoning": "clearly a scanner artefact",
        }]
        RetryTask(results_by_id=prior).finalize(fresh, prior)
        merged = prior["f1"]
        assert merged["retried"] is True
        assert merged["is_exploitable"] is False
        assert not merged.get("self_contradictory")
        assert "contradictions" not in merged

    def test_still_contradictory_retry_keeps_flag(self):
        # Two-direction: a retry that contradicts itself again must
        # stay flagged (with the fresh contradiction recorded).
        prior = _prior_with_flag()
        fresh = [{
            "finding_id": "f1",
            "is_true_positive": True,
            "is_exploitable": True,
            "exploitability_score": 0.9,
            "ruling": "false_positive",
            "reasoning": "solid reasoning",
        }]
        RetryTask(results_by_id=prior).finalize(fresh, prior)
        merged = prior["f1"]
        assert merged["retried"] is True
        assert merged["self_contradictory"] is True
        assert any(
            "is_exploitable=True" in c for c in merged["contradictions"]
        )
