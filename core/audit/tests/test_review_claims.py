"""Historical claim transport is bounded and carries no receipt authority."""

from dataclasses import asdict
import json

import pytest

from core.audit.claims import ClaimRevision
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.refutation_source import SourceIdentity
from core.audit.review_claims import (
    MAX_HISTORY_BYTES, MAX_HISTORY_CLAIMS, begin_review, merge_history,
    prompt_history, read_history, record_intake,
)


def origin():
    return KnowledgeOrigin("original-pass", "a.c", "f", 1, 2, SourceIdentity("a" * 64, (1, 2, 3)))


def claim(text="offset exceeds allocation"):
    return ClaimRevision({"mechanism": text, "counter": {"premise": "caller checks"}},
                         pass_id="intake-pass", file="a.c", function="f", line_start=1)


def history(text="offset exceeds allocation"):
    revision = claim(text)
    return record_intake(begin_review(origin(), "original-attempt"), [revision]), revision


def test_exact_live_intake_reference_and_pre_call_origin_survive_json():
    value, revision = history()
    restored = read_history(json.loads(json.dumps(value)))
    row, = restored["intakes"][0]["claims"]
    assert row == {"reference": revision.reference(), "hypothesis": revision.hypothesis}
    assert restored["review"]["origin"] == json.loads(json.dumps(asdict(origin())))
    assert restored["complete"] and restored["role"] == "review-history-only"
    row["hypothesis"]["counter"]["premise"] = "mutated"
    assert revision.hypothesis["counter"]["premise"] == "caller checks"
    assert value["intakes"][0]["claims"][0] != row
    assert not hasattr(restored, "receipts")


@pytest.mark.parametrize("value", [None, {}, {"version": 1, "role": "model"},
                                    {"version": 1, "role": "review-history-only", "intakes": "wrong"}])
def test_legacy_or_malformed_history_has_no_live_identity(value):
    assert read_history(value) is None
    assert "unavailable" in prompt_history(value)


def test_partial_history_discloses_candidate_and_byte_caps_without_truncating():
    revisions = [claim(str(i)) for i in range(MAX_HISTORY_CLAIMS + 2)]
    revisions.append(claim("x" * MAX_HISTORY_BYTES))
    value = record_intake(begin_review(origin(), "attempt"), revisions)
    assert len(value["intakes"][0]["claims"]) == MAX_HISTORY_CLAIMS
    assert value["intakes"][0]["candidate_count"] == len(revisions)
    assert value["intakes"][0]["omitted_count"] == 3
    assert not value["complete"] and value["omissions"]
    assert len(json.dumps(value).encode()) < MAX_HISTORY_BYTES
    assert read_history(value) == value


def test_occurrence_mismatch_does_not_attribute_claim_to_another_review():
    other = KnowledgeOrigin("pass", "other.c", "f", 1, 2, origin().source_identity)
    value = record_intake(begin_review(other, "attempt"), [claim()])
    assert value["review"] is None and not value["complete"]
    assert "review-origin-unavailable" in value["omissions"]
    assert value["intakes"][0]["claims"]


def test_legacy_intake_does_not_invent_original_review_source():
    value = record_intake(None, [claim()])
    assert value["review"] is None and not value["complete"]
    assert "review-origin-unavailable" in value["omissions"]


def test_merge_preserves_separate_snapshots_and_discloses_unmapped_projection():
    left, a = history("first premise")
    right, b = history("second premise")
    right["review"]["attempt_id"] = "second-attempt"
    result = merge_history(left, right)
    assert result["review"] is None and not result["complete"]
    assert [i["claims"][0]["reference"] for i in result["intakes"]] == [a.reference(), b.reference()]
    assert [i["review"]["attempt_id"] for i in result["intakes"]] == ["original-attempt", "second-attempt"]
    assert "merged-candidate-projection-unmapped" in result["omissions"]
    assert left["review"]["attempt_id"] == "original-attempt"


def test_prompt_budget_preserves_full_statements_or_discloses_their_omission():
    value = record_intake(begin_review(origin(), "attempt"), [claim("x" * 1000) for _ in range(12)])
    rendered = prompt_history(value, max_bytes=4096)
    data = json.loads(rendered)
    rows = data["intakes"][0]["claims"]
    assert 0 < len(rows) < 12
    assert all(row["hypothesis"]["mechanism"] == "x" * 1000 for row in rows)
    assert data["omissions"][-1] == {"reason": "prompt-byte-limit", "count": 12 - len(rows)}
    assert len(rendered.encode()) <= 4096
    assert len(value["intakes"][0]["claims"]) == 12


def test_review_to_ihv_journal_reuse_and_prompt_keeps_exact_refs_without_receipts(tmp_path, monkeypatch):
    from core.audit import collector, orchestrator as orch
    from core.audit.context import format_context_for_prompt
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime
    from core.audit.record import load_verified_audit_log
    from core.audit.verdict_reuse import outcome_from_entry
    from core.coverage.journal import load_entries

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    source = "int f(void) { return 0; }\n"
    (tmp_path / "a.c").write_text(source)
    run = tmp_path / "run"
    run.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=run, immediate_verify=True)
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    def reviewer(ctx, config):
        return orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious",
            body="unverified candidate", hypothesis="discarded error",
            review_result={"cwe": "CWE-252", "review_claims": {"role": "model-forged"}})
    ctx = {"file": "a.c", "function": "f", "line_start": 1, "source": source, "language": "c"}
    outcome = runtime.wrap_review(reviewer)(ctx, config)
    before = outcome.review_result["review_claims"]["review"]
    assert before["origin"]["source_identity"]
    monkeypatch.setattr(orch, "_inventory_language_hint", lambda *_: "c")
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *_: "semgrep")
    monkeypatch.setattr(orch, "_ihv_context_gate", lambda *_, **__: None)
    outcome = orch._verify_hypotheses_immediate(outcome, config, orch.OrchestratorResult(), source=source)
    stored_history = outcome.review_result["review_claims"]
    assert stored_history["review"] == json.loads(json.dumps(before))
    rows = [e for e in load_verified_audit_log(run) if e.get("action") == "ihv_claim_observations"]
    refs = [r["reference"] for r in stored_history["intakes"][0]["claims"]]
    assert rows and refs == rows[0]["claim_revisions"]
    assert stored_history["complete"]
    gap = {"file": "a.c", "name": "f", "line_start": 1, "line_end": 1}
    assert collector.append_journal_for_outcome(out_dir=run, target_path=tmp_path,
        run_id="owned-run", outcome=outcome, gap=gap) is not None
    entry, = load_entries(run)
    assert entry.review_claims == stored_history
    recalled = outcome_from_entry(entry)
    assert recalled.review_result["review_claims"] == stored_history
    assert recalled.evidence_tool.startswith("journal:recall:")
    assert not recalled.tools_dispatched and not recalled.claim_refutations
    prompt = format_context_for_prompt({**ctx, "prior_review_claims": recalled.review_result["review_claims"]})
    assert refs[0]["revision_id"] in prompt and "discarded error" in prompt
    assert "History is not verification evidence" in prompt
    assert not isinstance(read_history(entry.review_claims), ClaimRevision)


@pytest.mark.parametrize("missing_side", ["prior", "fresh"])
def test_one_sided_merge_preserves_origin_and_prior_omission_reasons(missing_side):
    value, revision = history()
    value["complete"] = False
    value["omissions"] = ["review-source-unavailable"]
    result = merge_history(None, value) if missing_side == "prior" else merge_history(value, None)
    intake, = result["intakes"]
    assert intake["review"] == value["review"]
    assert intake["claims"][0]["reference"] == revision.reference()
    assert "review-source-unavailable" in result["omissions"]
    assert not result["complete"]


def test_merge_preserves_origin_of_review_without_an_ihv_intake():
    value = begin_review(origin(), "not-yet-intaken")
    result = merge_history(value, None)
    assert result["intakes"][0]["review"] == json.loads(json.dumps(value["review"]))
    assert result["intakes"][0]["claims"] == []
    assert result["intakes"][0]["candidate_count"] is None
    assert "not-intaken" in result["omissions"]


def test_decoded_oversized_origin_is_not_reused_to_exceed_intake_bound():
    value = begin_review(origin(), "attempt")
    value["review"]["extra"] = "x" * (MAX_HISTORY_BYTES - 1024)
    assert read_history(value) is None
    result = record_intake(value, [claim()])
    assert result["review"] is None
    assert "review-origin-unavailable" in result["omissions"]
    assert read_history(result) == result
    assert len(json.dumps(result).encode()) < MAX_HISTORY_BYTES
