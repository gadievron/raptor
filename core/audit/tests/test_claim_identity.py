"""Pipeline claim lineage survives checker output without gaining authority."""

from types import SimpleNamespace
from uuid import UUID

import pytest

from core.audit.claims import ClaimRevision
from core.audit.claim_verification import ClaimVerification
from core.audit.record import load_verified_audit_log
from core.audit import orchestrator as orch
from core.audit.refutation_source import capture_source_identity
from core.audit.verification_results import ToolChainResult, VerificationScope


def claim(hypothesis=None, *, pass_id="owned-pass"):
    return ClaimRevision(hypothesis or {"mechanism": "discarded error"}, pass_id=pass_id,
                         file="a.c", function="f", line_start=1)


def test_pipeline_ids_ignore_model_fields_and_do_not_infer_lineage():
    hyp = {"mechanism": "discarded error", "claim_id": "model-chosen", "revision": 99}
    first, second = claim(hyp), claim(hyp)
    assert UUID(first.claim_id).hex == first.claim_id
    assert first.claim_id != "model-chosen" and first.claim_id != second.claim_id
    assert first.revision == second.revision == 1
    assert first.parent_revision is second.parent_revision is None


def test_statement_copies_and_explicit_revisions_do_not_inherit_evidence():
    hyp = {"mechanism": "discarded error", "nested": {"assumption": "caller checks"}}
    first = claim(hyp)
    hyp["nested"]["assumption"] = "mutated"
    detached = first.hypothesis
    detached["nested"]["assumption"] = "mutated again"
    assert first.hypothesis["nested"]["assumption"] == "caller checks"
    supported = ClaimVerification(first.hypothesis, ("semgrep:explicit-error-discard",), claim_revision=first)
    second = first.revise({"mechanism": "different premise"}, pass_id="next-owned-pass")
    assert second.claim_id == first.claim_id
    assert (second.revision, second.parent_revision) == (2, first.revision_id)
    fork = first.revise({"mechanism": "another premise"}, pass_id="next-owned-pass")
    assert fork.claim_id == second.claim_id
    assert fork.revision == second.revision == 2
    assert fork.parent_revision == second.parent_revision == first.revision_id
    assert fork.revision_id != second.revision_id
    assert fork.reference() != second.reference()
    assert second.pass_id != first.pass_id
    revised = ClaimVerification(second.hypothesis, claim_revision=second)
    assert revised.receipts == () and revised.binding is None
    assert supported.receipts == ("semgrep:explicit-error-discard",)
    with pytest.raises(ValueError, match="explicit claim revision"):
        ClaimVerification(second.hypothesis, claim_revision=first)


def test_legacy_and_unbound_evidence_do_not_gain_scope_from_claim_identity():
    hyp = {"mechanism": "discarded error"}
    assert ClaimVerification(hyp).claim_revision is None
    owned = ClaimVerification(hyp, claim_revision=claim(hyp))
    checked = owned.with_observation(("semgrep:explicit-error-discard",))
    assert checked.claim_revision is owned.claim_revision
    assert checked.binding is None
    assert owned.receipts == ()
    with pytest.raises(TypeError, match="ClaimRevision"):
        ClaimVerification(hyp, claim_revision={"claim_id": "model"})


@pytest.mark.parametrize("mode", ["prep", "chain", "refuted", "synthesis", "untested"])
def test_normal_immediate_dispatch_preserves_intake_identity(tmp_path, monkeypatch, mode):
    source = "int f(void) { return 0; }\n"
    (tmp_path / "a.c").write_text(source)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", immediate_verify=True)
    config.out_dir.mkdir()
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="",
                                hypothesis="discarded error", review_result={"cwe": "CWE-252"})
    results = orch.OrchestratorResult()
    monkeypatch.setattr(orch, "_inventory_language_hint", lambda *_: "c")
    monkeypatch.setattr(orch, "_get_llm_client", lambda *_: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *_: [])
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *_: "semgrep" if mode == "prep" else None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *_, **__: (
        [] if mode == "synthesis" else [{"type": "joern" if mode == "untested" else "semgrep"}]))
    binding = VerificationScope("a.c", "f", 1, "discarded error", capture_source_identity(tmp_path, "a.c"))
    def chain(*args, **kwargs):
        checked = ToolChainResult(() if mode == "refuted" else ("semgrep:explicit-error-discard",),
                                  file=binding.file, function=binding.function, line_start=1,
                                  hypothesis=binding.hypothesis, source_identity=binding.source_identity)
        if mode == "refuted":
            checked.observe("semgrep", "refuted", "explicit-error-discard")
        return checked
    monkeypatch.setattr(orch, "_run_tool_chain", chain)
    monkeypatch.setattr(orch, "_bind_synthesis_request", lambda *_: (SimpleNamespace(binding=binding), source))
    monkeypatch.setattr(orch, "_try_ihv_synthesis", lambda *_: "semgrep:explicit-error-discard")
    monkeypatch.setattr(orch, "_ihv_context_gate", lambda *_, **__: None)
    observed = []
    original = ClaimVerification.with_observation
    def observe(self, *args, **kwargs):
        replacement = original(self, *args, **kwargs)
        observed.append((self.claim_revision, replacement.claim_revision))
        return replacement
    monkeypatch.setattr(ClaimVerification, "with_observation", observe)
    orch._verify_hypotheses_immediate(outcome, config, results, source=source,
                                     synthesis_counter=orch.AtomicSynthesisCounter(1))
    events = [e for e in load_verified_audit_log(config.out_dir) if e.get("action") == "ihv_claim_observations"]
    assert len(events) == 1
    refs = events[0]["claim_revisions"]
    assert len(refs) == 1
    ref = refs[0]
    assert UUID(ref["claim_id"]).hex == ref["claim_id"]
    assert UUID(ref["revision_id"]).hex == ref["revision_id"]
    assert UUID(ref["pass_id"]).hex == ref["pass_id"]
    assert (ref["file"], ref["function"], ref["line_start"], ref["revision"]) == ("a.c", "f", 1, 1)
    assert ref["parent_revision"] is None
    if mode == "untested":
        assert observed == []
    else:
        assert observed and all(before is after for before, after in observed)
        assert observed[-1][0].claim_id == ref["claim_id"]
    assert events[0]["role"] == "unadjudicated_observation"
    if mode in {"prep", "untested", "refuted"}:
        assert events[0]["producer_bindings"] == [None]
    else:
        assert events[0]["producer_bindings"][0]["source_identity"]["sha256"] == binding.source_identity.sha256


def test_partial_statement_retains_lineage_without_inventing_producer_scope(tmp_path):
    from core.audit.check_trace import record_claim_observations

    first = claim({"mechanism": "a" * (80 * 1024)})
    record_claim_observations(tmp_path, file="other.c", function="other", line_start=9,
                              verifications=[ClaimVerification(first.hypothesis, claim_revision=first)])
    rows = load_verified_audit_log(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert not row["observations"]["complete"]
    assert row["claim_revisions"] == [first.reference()]
    assert row["claim_revisions_complete"]
    assert row["producer_bindings"] == [None]
    assert row["consumer_scope"] != {k: v for k, v in first.reference().items()
                                    if k in {"file", "function", "line_start"}}


def test_oversized_lineage_is_explicitly_unavailable(tmp_path):
    from core.audit.check_trace import record_claim_observations

    first = ClaimRevision({"mechanism": "discarded error"}, pass_id="p", file="a.c",
                          function="f" * (140 * 1024), line_start=1)
    record_claim_observations(tmp_path, file="a.c", function="f", line_start=1,
                              verifications=[ClaimVerification(first.hypothesis, claim_revision=first)])
    row, = load_verified_audit_log(tmp_path)
    assert row["claim_revisions"] is None
    assert not row["claim_revisions_complete"]
    assert "claim_revisions_size_limit" in row["metadata_omissions"]
    assert row["observations"]["complete"]


def test_material_variants_ignore_ranking_but_keep_counter_contracts_distinct():
    from core.audit.claims import hypothesis_material_key

    original = {"mechanism": "length controls a copy", "counter_scope": "cross_function",
                "guard_type": "bounds", "assumed_property": "count <= allocation", "confidence": "low"}
    first = hypothesis_material_key(original, default_cwe="CWE-787")
    assert first == hypothesis_material_key({**original, "confidence": "high", "is_primary": True,
                                            "counter": "", "cwe": " CWE-787 "})
    assert first != hypothesis_material_key({**original, "assumed_property": "byte_count <= allocation"}, default_cwe="CWE-787")
    assert first != hypothesis_material_key({**original, "counter_scope": "local"}, default_cwe="CWE-787")
    assert first != hypothesis_material_key({**original, "cwe": "CWE-190"}, default_cwe="CWE-787")
    assert hypothesis_material_key({**original, "counter": {"unknown": "shape"}}) is None
