"""Late synthesis must publish the claim given to its producer."""

from copy import deepcopy

import pytest

from core.audit import orchestrator as orch, checker_synthesis
from core.audit.findings_export import export_findings, write_graded_findings
from core.json import load_json


def test_late_synthesis_receives_selected_claim_without_mutating_primary(tmp_path, monkeypatch):
    source = "int f(int n) { return n; }"
    (tmp_path / "a.c").write_text(source, encoding="utf-8")
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    primary = "unrelated primary concern"
    selected = "discarded error"
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="Owned fixture",
        hypothesis=primary, review_result={"hypothesis": primary, "cwe": "CWE-190"})
    result = orch.OrchestratorResult()
    result.outcomes = [outcome]
    seen = []
    def produce(candidate, cfg, **kwargs):
        seen.append((candidate.hypothesis, candidate.review_result["hypothesis"], kwargs["cwe"]))
        return checker_synthesis.OnDemandSynthesisResult(confirmed=False)
    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    orch._synthesize_unmapped_suspicious(result, config, 0, outcome, selected, "CWE-252", source)
    assert seen == [(selected, selected, "CWE-252")]
    assert outcome.hypothesis == outcome.review_result["hypothesis"] == primary


PRIMARY = "unrelated primary concern"
SELECTED = "discarded error"
RECEIPT = "semgrep:synth-other.c.g.CWE-252.0"


def _subject(tmp_path, monkeypatch):
    source = "int f(int n) { return n; }"
    (tmp_path / "a.c").write_text(source, encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out_dir)
    claims = [{"mechanism": PRIMARY, "cwe": "CWE-190"}, {"mechanism": SELECTED, "cwe": "CWE-252"}]
    original = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="Owned fixture",
        hypothesis=PRIMARY, hypotheses=deepcopy(claims),
        review_result={"hypothesis": PRIMARY, "cwe": "CWE-190", "cwe_class": "CWE-190",
                       "hypotheses": deepcopy(claims)})
    result = orch.OrchestratorResult()
    result.outcomes = [original]
    result.suspicious = 1
    monkeypatch.setattr(orch, "_guard_blocks_promotion", lambda *a, **kw: None)
    return config, original, result, source


@pytest.mark.parametrize("selected", [PRIMARY, SELECTED])
def test_promoted_claim_and_json_match_the_synthesis_input(tmp_path, monkeypatch, selected):
    cfg, original, result, source = _subject(tmp_path, monkeypatch)
    before = deepcopy(original.review_result)
    calls = []

    def produce(candidate, config, **kwargs):
        calls.append((candidate.hypothesis, deepcopy(candidate.review_result), kwargs["cwe"]))
        return checker_synthesis.OnDemandSynthesisResult(confirmed=True, stamp=RECEIPT, cost_usd=0.01)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    orch._synthesize_unmapped_suspicious(result, cfg, 0, original, selected, "CWE-252", source)
    assert len(calls) == 1
    assert calls[0][0] == calls[0][1]["hypothesis"] == selected
    assert calls[0][1]["cwe"] == calls[0][1]["cwe_class"] == calls[0][2] == "CWE-252"
    promoted = result.outcomes[0]
    assert promoted is not original
    assert promoted.hypothesis == promoted.review_result["hypothesis"] == selected
    assert promoted.review_result["cwe"] == promoted.review_result["cwe_class"] == "CWE-252"
    assert promoted.evidence_tool == RECEIPT
    assert result.findings == result.sweep_promoted == result.ondemand_synthesized == 1
    assert result.suspicious == 0 and result.total_cost_usd == pytest.approx(0.01)
    assert original.hypothesis == PRIMARY and original.review_result == before
    write_graded_findings(export_findings(result.outcomes), cfg.out_dir)
    finding = load_json(cfg.out_dir / "findings-graded.json")["findings"][0]
    assert finding["hypothesis"] == selected
    assert finding["discovery"]["evidence_tool"] == RECEIPT


@pytest.mark.parametrize("mode", ["unconfirmed", "self_match", "guarded", "premise"])
def test_refused_secondary_never_relabels_original_primary(tmp_path, monkeypatch, mode):
    cfg, original, result, source = _subject(tmp_path, monkeypatch)
    selected_claims = []

    def produce(candidate, config, **kwargs):
        selected_claims.append(candidate.hypothesis)
        stamp = "semgrep:synth-a.c.f.CWE-252.0" if mode == "self_match" else RECEIPT
        return checker_synthesis.OnDemandSynthesisResult(confirmed=mode != "unconfirmed", stamp=stamp, cost_usd=0.01)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    if mode == "guarded":
        monkeypatch.setattr(orch, "_guard_blocks_promotion", lambda *a, **kw: "owned guard control")
    if mode == "premise":
        def premise(claim, receipts):
            assert claim["mechanism"] == SELECTED
            assert receipts == [RECEIPT]
            return True

        monkeypatch.setattr(orch, "_premise_blocks_confirm", premise)
        monkeypatch.setattr(orch, "_note_premise_blocked_validation", lambda *a, **kw: None)
    orch._synthesize_unmapped_suspicious(result, cfg, 0, original, SELECTED, "CWE-252", source)
    assert selected_claims == [SELECTED]
    assert result.outcomes[0] is original
    assert original.hypothesis == original.review_result["hypothesis"] == PRIMARY
    assert original.review_result["cwe"] == original.review_result["cwe_class"] == "CWE-190"
    assert not original.evidence_tool
    assert result.suspicious == result.ondemand_synthesized == 1 and result.findings == 0
    assert result.total_cost_usd == pytest.approx(0.01)
    if mode == "self_match":
        assert original.review_result["ondemand_synth_hypothesis"] == SELECTED


@pytest.mark.parametrize("field", ["file", "function", "line", "hypothesis", "review_hypothesis", "cwe", "cwe_class"])
@pytest.mark.parametrize("phase", ["producer", "context"])
def test_revised_candidate_cannot_publish_with_old_receipt(tmp_path, monkeypatch, field, phase):
    cfg, original, result, source = _subject(tmp_path, monkeypatch)
    before = deepcopy(original.review_result)
    candidates = []

    def revise(candidate):
        if field in {"review_hypothesis", "cwe", "cwe_class"}:
            candidate.review_result["hypothesis" if field == "review_hypothesis" else field] = "changed"
        else:
            setattr(candidate, field, 9 if field == "line" else "changed")

    def produce(candidate, config, **kwargs):
        candidates.append(candidate)
        if phase == "producer":
            revise(candidate)
        return checker_synthesis.OnDemandSynthesisResult(confirmed=True, stamp=RECEIPT, cost_usd=0.01)

    def guard(*args, **kwargs):
        if phase == "context":
            revise(candidates[0])
        return None

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    monkeypatch.setattr(orch, "_guard_blocks_promotion", guard)
    orch._synthesize_unmapped_suspicious(result, cfg, 0, original, SELECTED, "CWE-252", source)
    assert len(candidates) == 1
    assert result.outcomes[0] is original and original.review_result == before
    assert result.findings == 0 and result.suspicious == 1
    assert result.ondemand_synthesized == 1 and result.total_cost_usd == pytest.approx(0.01)
    write_graded_findings(export_findings(result.outcomes), cfg.out_dir)
    checks = load_json(cfg.out_dir / "verification-checks.json")["checks"]
    rejection = next(c for c in checks if c["rule_id"] == "claim-scope-rejected")
    assert rejection["outcome"] == "inconclusive"
    assert rejection["scope"]["hypothesis"] == SELECTED
    assert rejection["scope"]["source_identity"] is not None


def test_synthesis_candidate_owns_nested_review_data(tmp_path, monkeypatch):
    cfg, original, result, source = _subject(tmp_path, monkeypatch)
    before_review, before_claims = deepcopy(original.review_result), deepcopy(original.hypotheses)

    def produce(candidate, config, **kwargs):
        candidate.review_result["hypotheses"][0]["mechanism"] = "changed nested review"
        candidate.hypotheses[0]["mechanism"] = "changed nested outcome"
        return checker_synthesis.OnDemandSynthesisResult(confirmed=False)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    orch._synthesize_unmapped_suspicious(result, cfg, 0, original, SELECTED, "CWE-252", source)
    assert original.review_result == before_review
    assert original.hypotheses == before_claims


@pytest.mark.parametrize("change", ["stale", "edit", "delete", "restore", "context"])
def test_source_binding_prevents_stale_late_synthesis_promotion(tmp_path, monkeypatch, change):
    cfg, original, result, source = _subject(tmp_path, monkeypatch)
    path = tmp_path / "a.c"
    calls = []

    def produce(candidate, config, **kwargs):
        calls.append(kwargs["source_snippet"])
        if change in {"edit", "restore"}:
            path.write_text(source + "\n// changed revision", encoding="utf-8")
        elif change == "delete":
            path.unlink()
        if change == "restore":
            path.write_text(source, encoding="utf-8")
        return checker_synthesis.OnDemandSynthesisResult(confirmed=True, stamp=RECEIPT, cost_usd=0.01)

    def guard(*args, **kwargs):
        if change == "context":
            path.write_text(source + "\n// changed in context", encoding="utf-8")
        return None

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    monkeypatch.setattr(orch, "_guard_blocks_promotion", guard)
    snippet = source.replace("return n;", "return 0;") if change == "stale" else source
    orch._synthesize_unmapped_suspicious(result, cfg, 0, original, SELECTED, "CWE-252", snippet)
    assert result.outcomes[0] is original and original.status == "suspicious"
    assert original.hypothesis == original.review_result["hypothesis"] == PRIMARY
    assert result.findings == 0
    assert calls == ([] if change == "stale" else [source])
    assert result.ondemand_synthesized == (0 if change == "stale" else 1)
    assert result.total_cost_usd == pytest.approx(0 if change == "stale" else 0.01)
    write_graded_findings(export_findings(result.outcomes), cfg.out_dir)
    checks = load_json(cfg.out_dir / "verification-checks.json")["checks"]
    rule = "source-input-unbound" if change == "stale" else "source-version-drift"
    rejection = next(c for c in checks if c["rule_id"] == rule)
    assert rejection["scope"]["hypothesis"] == SELECTED
    assert rejection["outcome"] == "inconclusive"
    if change == "stale":
        assert "checker_synthesis" in original.tools_skipped
        assert rejection["result"]["data"]["details"]["checker_execution"] == "not_run"
    else:
        assert rejection["scope"]["source_identity"] is not None
        assert rejection["result"]["data"]["details"]["prior_receipts"] == [RECEIPT]
