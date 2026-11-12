"""Model consistency labels cannot replace admitted refutation or withdrawal."""

from copy import deepcopy

import pytest

from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult, ReviewOutcome, _demote_self_contradictions
from core.llm.providers import StructuredResponse


HYPOTHESES = [{"mechanism": "copy length exceeds the local buffer", "confidence": "refuted",
               "counter": "the length is clamped to sizeof(buf) on the line above the copy",
               "counter_scope": "local"}]


class CapturedReviewer:
    def __init__(self, status="suspicious"):
        self.calls = 0
        self.status = status

    def generate_structured(self, *args, **kwargs):
        self.calls += 1
        return StructuredResponse(result={"status": self.status, "body": "Review assessment",
            "hypotheses": deepcopy(HYPOTHESES)}, raw="", cost=.125, model="captured")


@pytest.mark.parametrize("deepen", [False, True], ids=["initial", "deepen"])
def test_renderer_keeps_model_refutation_as_unverified_judgment(tmp_path, deepen):
    source = "void f(char *p, int n) { char buf[8]; memcpy(buf, p, n); }\n"
    (tmp_path / "unit.c").write_text(source)
    client = CapturedReviewer()
    review = make_review_fn(client, escalate_clean=False)
    outcome = review({"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
                      "source": source, "language": "c", "deepen": deepen},
                     OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert client.calls == 1 and outcome.cost_usd == .125
    assert outcome.status == "suspicious"
    assert outcome.hypotheses == HYPOTHESES
    assert not outcome.review_result.get("all_refuted_demotion")
    assert outcome.review_result["all_refuted_demotion_withheld"]
    assert "deepen-verified" not in outcome.review_result.values()


def test_postloop_consistency_diagnostic_preserves_canonical_assessment():
    outcome = ReviewOutcome(file="unit.c", function="f", line=1, status="suspicious",
        body="Review assessment", hypotheses=deepcopy(HYPOTHESES), cost_usd=.125, model="captured")
    result = OrchestratorResult(outcomes=[outcome], suspicious=1, total_cost_usd=.125)
    _demote_self_contradictions(result)
    assert result.outcomes == [outcome] and result.outcomes[0] is outcome
    assert (outcome.status, result.suspicious, result.clean, result.total_cost_usd) == ("suspicious", 1, 0, .125)
    assert outcome.body == "Review assessment" and outcome.hypotheses == HYPOTHESES
    assert outcome.review_result["all_refuted_demotion_withheld"] == "explicit-withdrawal-required"
    assert len(result.scorecard_events) == 1
    _demote_self_contradictions(result)
    assert len(result.scorecard_events) == 1


def test_independent_clean_model_assessment_remains_a_judgment(tmp_path):
    client = CapturedReviewer("clean")
    outcome = make_review_fn(client, escalate_clean=False)(
        {"file": "unit.c", "function": "f", "line_start": 1, "source": "int f(void) { return 0; }"},
        OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert outcome.status == "clean"
    assert not outcome.review_result.get("all_refuted_demotion")
    assert client.calls == 1
