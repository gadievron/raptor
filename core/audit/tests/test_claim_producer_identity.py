"""Claim lineage follows current producer calls, not cached checker objects."""

import pytest

from core.audit import orchestrator as orch
from core.audit.claims import ClaimRevision
from core.audit.record import load_verified_audit_log
from core.audit.refutation_source import capture_source_identity
from core.audit.sweep import SweepResult
from core.audit.verification_results import ClaimRefutation, ToolChainResult


SOURCE = "int f(void) { return 0; }\n"
SCOPE = {"file": "a.c", "function": "f", "line_start": 1, "hypothesis": "discarded error"}


def revision(pass_id="one", **changes):
    scope = {**SCOPE, **changes}
    return ClaimRevision({"mechanism": scope.pop("hypothesis")}, pass_id=pass_id, **scope)


def setup(tmp_path):
    (tmp_path / "a.c").write_text(SOURCE)
    rule = tmp_path / "rule.yaml"
    rule.write_text("rules: []\n")
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    config.out_dir.mkdir()
    return config, [{"type": "semgrep", "config": {"rule": str(rule)}}]


def run(config, chain, claim):
    return orch._run_tool_chain(chain, config=config, file_path="a.c", function_name="f",
                                line_start=1, source=SOURCE, hypothesis="discarded error", claim_revision=claim)


def sweep(verdict="confirmed"):
    return SweepResult(tool="semgrep", file_path="a.c", function_name="f", outcome=verdict,
                       rule_id="fixture", matches=[{"line": 1}] if verdict == "confirmed" else [])


@pytest.mark.parametrize("change", [{"file": "other.c"}, {"function": "g"},
                                    {"line_start": 2}, {"hypothesis": "different concern"}])
def test_wrong_producer_occurrence_cannot_adopt_lineage(change):
    claim = revision(**change)
    with pytest.raises(ValueError, match="producer scope"):
        ToolChainResult(**SCOPE, claim_revision=claim)
    with pytest.raises(ValueError, match="producer scope"):
        ClaimRefutation(**SCOPE, checks=(), claim_revision=claim)


def test_legacy_lineage_remains_unavailable_and_references_are_detached():
    legacy = ToolChainResult(**SCOPE)
    assert legacy.claim_revision is None
    legacy.observe("semgrep", "refuted", "fixture")
    assert "claim_reference" not in legacy.refutation_record(**SCOPE)
    claim = revision()
    result = ToolChainResult(**SCOPE, claim_revision=claim)
    result.observe("semgrep", "refuted", "fixture")
    record = result.refutation_record(**SCOPE)
    assert record["claim_reference"] == claim.event_reference()
    record["claim_reference"]["claim_id"] = "tampered"
    assert result.claim_revision.claim_id == claim.claim_id != "tampered"
    assert result.source_identity is None


def test_memo_hit_keeps_current_claim_identity_without_another_execution(tmp_path, monkeypatch):
    config, chain = setup(tmp_path)
    calls = []
    def checker(**kwargs):
        calls.append(kwargs)
        return sweep()
    monkeypatch.setattr(orch, "run_semgrep_sweep", checker)
    first, second = revision("one"), revision("two")
    a, b = run(config, chain, first), run(config, chain, second)
    assert len(calls) == 1
    assert config.sweep_memo.hits == 1
    assert a.claim_revision is first and b.claim_revision is second
    rows = [r for r in load_verified_audit_log(config.out_dir) if r.get("action") == "verification_check"]
    assert [r["claim_reference"] for r in rows] == [first.event_reference(), second.event_reference()]
    assert all(r["scope"]["source_identity"]["sha256"] == a.source_identity.sha256 for r in rows)
    assert a == b and a.source_identity == b.source_identity


@pytest.mark.parametrize("failure", ["stale_input", "source_drift"])
def test_source_rejections_keep_lineage_without_restoring_authority(tmp_path, monkeypatch, failure):
    config, chain = setup(tmp_path)
    claim = revision()
    calls = []
    def checker(**kwargs):
        calls.append(kwargs)
        (tmp_path / "a.c").write_text(SOURCE + "/* changed */\n")
        return sweep()
    monkeypatch.setattr(orch, "run_semgrep_sweep", checker)
    if failure == "stale_input":
        (tmp_path / "a.c").write_text(SOURCE.replace("return 0", "return 1"))
    result = run(config, chain, claim)
    assert not result
    assert result.claim_revision is claim
    rows = [r for r in load_verified_audit_log(config.out_dir)
            if r.get("action") == "verification_check" and r.get("tool") == "source_binding"]
    assert rows and all(r["claim_reference"] == claim.event_reference() for r in rows)
    assert all(r["outcome"] == "inconclusive" for r in rows)
    if failure == "stale_input":
        assert calls == [] and result.source_identity is None
    else:
        assert len(calls) == 1
        assert result.source_identity != capture_source_identity(tmp_path, "a.c")


@pytest.mark.parametrize("fail_telemetry", [False, True])
def test_refutation_reuse_identity_does_not_change_receipt_authority(tmp_path, monkeypatch, fail_telemetry):
    config, _ = setup(tmp_path)
    source = capture_source_identity(tmp_path, "a.c")
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="",
                                hypothesis="discarded error")
    def checked(claim):
        result = ToolChainResult(**SCOPE, source_identity=source, claim_revision=claim)
        result.observe("semgrep", "refuted", "fixture")
        return result
    first, second = revision("one"), revision("two")
    a, b = checked(first), checked(second)
    assert a.refutation(**SCOPE) == b.refutation(**SCOPE)
    assert orch._retain_claim_refutation(outcome, a, config, hypothesis=SCOPE["hypothesis"], phase="ihv")
    if fail_telemetry:
        def fail(*args, **kwargs):
            raise OSError("owned telemetry failure")
        monkeypatch.setattr(orch, "append_audit_log", fail)
    assert orch._retain_claim_refutation(outcome, b, config, hypothesis=SCOPE["hypothesis"], phase="ihv")
    assert len(outcome.claim_refutations) == 1
    assert outcome.claim_refutations[0].matches(**SCOPE, source_identity=source)
    rows = load_verified_audit_log(config.out_dir)
    original, = [r for r in rows if r.get("action") == "ihv_refutation"]
    assert original["claim_reference"] == first.event_reference()
    reused = [r for r in rows if r.get("action") == "claim_refutation_reuse"]
    assert len(reused) == (0 if fail_telemetry else 1)
    if reused:
        assert reused[0]["claim_reference"] == second.event_reference()
        assert reused[0]["role"] == "context_provenance_not_verification_evidence"


@pytest.mark.parametrize("verdict", ["confirmed", "refuted"])
def test_normal_immediate_review_links_intake_and_producer_observations(tmp_path, monkeypatch, verdict):
    config, chain = setup(tmp_path)
    monkeypatch.setattr(orch, "run_semgrep_sweep", lambda **kwargs: sweep(verdict))
    monkeypatch.setattr(orch, "_get_llm_client", lambda *_: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *_: [])
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *_: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *_, **__: chain)
    monkeypatch.setattr(orch, "_ihv_context_gate", lambda *_, **__: None)
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="",
                                hypothesis="discarded error", review_result={"cwe": "CWE-252"})
    orch._verify_hypotheses_immediate(outcome, config, orch.OrchestratorResult(), source=SOURCE)
    rows = load_verified_audit_log(config.out_dir)
    intake, = [r for r in rows if r.get("action") == "ihv_claim_observations"]
    claim = intake["claim_revisions"][0]
    reference = {k: claim[k] for k in ("claim_id", "revision_id")}
    check, = [r for r in rows if r.get("action") == "verification_check" and r.get("tool") == "semgrep"]
    assert check["claim_reference"] == reference
    if verdict == "refuted":
        refutation, = [r for r in rows if r.get("action") == "ihv_refutation"]
        assert refutation["claim_reference"] == reference
        assert refutation["source_identity"] == check["scope"]["source_identity"]
