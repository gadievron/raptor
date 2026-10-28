"""Gate-resolution demotes open-discovery items to dormant, not dark.

Checklist-sourced suspicious outcomes that lack tool coverage become
``dark`` (the class is tool-blind — needs concrete verification).
Open-discovery items (``from_composition=True`` on review_result) become
``dormant`` instead: low-prior LLM hypotheses with no tool support are
below the reporting threshold.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

_REPO_ROOT = str(Path(__file__).resolve().parents[3])

from core.audit.orchestrator import (
    OrchestratorResult,
    ReviewOutcome,
    _commit_outcome,
    _resolve_gate_demoted,
)


# ── helpers ────────────────────────────────────────────────────────────

def _make_result(*outcomes: ReviewOutcome) -> OrchestratorResult:
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
    r.dormant = 0
    r.clean = 0
    return r


def _suspicious(
    file: str = "src/app.py",
    func: str = "handle",
    *,
    from_composition: bool = False,
    gate_demoted: bool = True,
) -> ReviewOutcome:
    body_prefix = "[gate violation: no evidence]\n\n" if gate_demoted else ""
    rr: dict = {}
    if from_composition:
        rr["from_composition"] = True
    return ReviewOutcome(
        file=file,
        function=func,
        status="suspicious",
        body=body_prefix + "Hypothesis text",
        hypothesis="Hypothesis text",
        review_result=rr or None,
    )


@dataclass
class _StubConfig:
    out_dir: Path = Path("/dev/null")
    target_path: str = "/tmp/target"
    _verdicts_finalized: bool = False


# ── _commit_outcome stamps from_composition ────────────────────────────

class TestCommitOutcomeCompositionStamp:
    def test_stamps_from_composition_on_outcome(self, tmp_path):
        gap = {
            "file": "src/app.py",
            "name": "handle",
            "from_composition": True,
        }
        outcome = ReviewOutcome(
            file="src/app.py",
            function="handle",
            status="suspicious",
            body="test",
        )
        config = _StubConfig(out_dir=tmp_path)

        with patch("core.audit.collector.append_journal_for_outcome"), \
             patch("core.audit.orchestrator._resolved_run_id", return_value="r1"), \
             patch("core.audit.orchestrator.append_audit_log"):
            _commit_outcome(config, outcome, gap)

        assert outcome.review_result is not None
        assert outcome.review_result["from_composition"] is True

    def test_no_stamp_without_flag(self, tmp_path):
        gap = {
            "file": "src/app.py",
            "name": "handle",
        }
        outcome = ReviewOutcome(
            file="src/app.py",
            function="handle",
            status="clean",
            body="ok",
        )
        config = _StubConfig(out_dir=tmp_path)

        with patch("core.audit.collector.append_journal_for_outcome"), \
             patch("core.audit.orchestrator._resolved_run_id", return_value="r1"), \
             patch("core.audit.orchestrator.append_audit_log"):
            _commit_outcome(config, outcome, gap)

        rr = outcome.review_result
        assert rr is None or "from_composition" not in rr

    def test_preserves_existing_review_result(self, tmp_path):
        gap = {
            "file": "src/app.py",
            "name": "handle",
            "from_composition": True,
        }
        outcome = ReviewOutcome(
            file="src/app.py",
            function="handle",
            status="suspicious",
            body="test",
            review_result={"cwe": "CWE-79"},
        )
        config = _StubConfig(out_dir=tmp_path)

        with patch("core.audit.collector.append_journal_for_outcome"), \
             patch("core.audit.orchestrator._resolved_run_id", return_value="r1"), \
             patch("core.audit.orchestrator.append_audit_log"):
            _commit_outcome(config, outcome, gap)

        assert outcome.review_result["cwe"] == "CWE-79"
        assert outcome.review_result["from_composition"] is True


# ── gate resolution: composition → dormant, checklist → dark ──────────

class TestGateResolutionCompositionDemotion:
    def _resolve(self, *outcomes: ReviewOutcome) -> OrchestratorResult:
        result = _make_result(*outcomes)
        config = _StubConfig()
        with patch(
            "core.audit.orchestrator._has_mechanical_corroboration",
            return_value=False,
        ), patch(
            "core.audit.orchestrator._probe_backed_suspicious",
            return_value=False,
        ):
            _resolve_gate_demoted(
                result,
                config,
                sarif_cache=None,
                checklist=None,
                available_tools={"joern": True},
            )
        return result

    def test_checklist_item_becomes_dark(self):
        outcome = _suspicious(from_composition=False)
        result = self._resolve(outcome)
        assert result.outcomes[0].status == "dark"

    def test_composition_item_becomes_dormant(self):
        outcome = _suspicious(from_composition=True)
        result = self._resolve(outcome)
        assert result.outcomes[0].status == "dormant"

    def test_mixed_batch(self):
        checklist_item = _suspicious(
            file="a.py", func="f1", from_composition=False,
        )
        discovery_item = _suspicious(
            file="b.py", func="f2", from_composition=True,
        )
        result = self._resolve(checklist_item, discovery_item)
        assert result.outcomes[0].status == "dark"
        assert result.outcomes[1].status == "dormant"

    def test_dormant_counter_incremented_for_both(self):
        checklist_item = _suspicious(
            file="a.py", func="f1", from_composition=False,
        )
        discovery_item = _suspicious(
            file="b.py", func="f2", from_composition=True,
        )
        result = self._resolve(checklist_item, discovery_item)
        assert result.dormant == 2
        assert result.suspicious == 0

    def test_resolves_without_joern(self):
        outcome = _suspicious(from_composition=False)
        result = _make_result(outcome)
        config = _StubConfig()
        with patch(
            "core.audit.orchestrator._has_mechanical_corroboration",
            return_value=False,
        ), patch(
            "core.audit.orchestrator._probe_backed_suspicious",
            return_value=False,
        ):
            _resolve_gate_demoted(
                result,
                config,
                sarif_cache=None,
                checklist=None,
                available_tools={"joern": False},
            )
        assert result.outcomes[0].status == "dark"
        assert result.suspicious == 0
