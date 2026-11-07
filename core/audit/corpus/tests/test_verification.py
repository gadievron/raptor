"""Corpus evidence snapshots cannot borrow another claim's observations."""

from copy import deepcopy
import json

import pytest

from core.audit.corpus import run_corpus as runner
from core.audit.corpus import verification
from core.audit.corpus.corpus_metrics import compute_metrics
from core.audit.corpus.label import FunctionLabel, SourcePin
from core.json import dumps_artifact


def _label(fid="a.c:f", line=1, repo="fixture"):
    return FunctionLabel(function_id=fid, bug_class="auth", expected_status="finding", rationale="Fixture",
                         source=SourcePin(repo, "a" * 40, "a.c", line, line + 1),
                         labeler="fixture", labeled_at="2026-01-01")


def _row(fid="a.c:f", actual="suspicious", hypothesis="Fixture claim"):
    return {"function_id": fid, "bug_class": "auth", "expected": "finding", "actual": actual,
            "hypothesis": hypothesis, "match": actual in ("finding", "suspicious")}


def _artifacts(root, *, qualified="", line=1, hypothesis="Fixture claim", status="suspicious"):
    root.mkdir(exist_ok=True)
    finding = {"id": "finding-1", "file": "a.c", "function": "f", "line": line,
               "hypothesis": hypothesis, "status": status,
               "verification_trace": {
                   "scope": {"file": "a.c", "function": "f", "function_qualified": qualified, "line": line},
                   "check_results": {"artifact": "verification-checks.json", "status": "recorded",
                                     "references": [{"id": "check-1", "matches_final_claim": True}]}}}
    check = {"id": "check-1", "scope": {"file": "a.c", "function": "f", "line_start": line,
                                         "hypothesis": hypothesis, "source_identity": {"sha256": "b" * 64}},
             "tool": "fixture", "outcome": "inconclusive", "result": {"complete": True, "data": {"details": {}}}}
    graded = {"findings": [finding]}
    sidecar = {"schema_version": 1, "checks": [check]}
    _save(root, graded, sidecar)
    return graded, sidecar


def _save(root, graded, sidecar):
    (root / "findings-graded.json").write_text(json.dumps(graded))
    (root / "verification-checks.json").write_text(json.dumps(sidecar))


def test_matching_snapshot_preserves_scoring_and_does_not_copy_group_totals(tmp_path):
    graded, sidecar = _artifacts(tmp_path)
    sidecar["checks"].append({**sidecar["checks"][0], "id": "unrelated", "outcome": "confirmed"})
    graded["verification_summary"] = {"observations": {"retained": {"records": 999}}}
    _save(tmp_path, graded, sidecar)
    rows = [_row()]
    original = deepcopy(rows[0])
    before = compute_metrics(rows)
    verification.annotate_verification(rows, [_label()], tmp_path)
    assert compute_metrics(rows) == before
    assert {k: rows[0][k] for k in original} == original
    evidence = rows[0]["verification"]
    assert evidence["status"] == "recorded"
    assert evidence["integrity_revalidated"] is False
    assert evidence["history_complete"] is False
    assert evidence["observations"]["matching_final_claim"]["outcomes"] == {"inconclusive": 1}
    assert evidence["observations"]["other_claims"]["records"] == 0


@pytest.mark.parametrize("fid,qualified,line,recorded", [
    ("a.c:Owner.f", "Owner.f", 1, True),
    ("a.c:Owner.f@v2", "Owner.f", 1, True),
    ("a.c:Owner.f", "Other.f", 1, False),
    ("a.c:Owner.f", "Owner.f", 20, False),
])
def test_receiver_version_and_location_are_not_interchangeable(tmp_path, fid, qualified, line, recorded):
    _artifacts(tmp_path, qualified=qualified, line=line)
    rows = [_row(fid)]
    verification.annotate_verification(rows, [_label(fid)], tmp_path)
    assert (rows[0]["verification"]["status"] == "recorded") is recorded


def test_missing_receiver_cannot_disambiguate_overlapping_labels(tmp_path):
    _artifacts(tmp_path)
    labels = [_label("a.c:Owner.f"), _label("a.c:Other.f")]
    rows = [_row(label.function_id) for label in labels]
    verification.annotate_verification(rows, labels, tmp_path)
    assert all(row["verification"]["status"] == "unavailable" for row in rows)
    assert all(row["verification"]["reason"] == "ambiguous_label_scope" for row in rows)


@pytest.mark.parametrize("change", ["claim", "verdict", "duplicate_finding", "duplicate_check", "check_scope", "claim_flag", "artifact_path"])
def test_mismatched_or_ambiguous_evidence_stays_unavailable(tmp_path, change):
    graded, sidecar = _artifacts(tmp_path)
    finding, check = graded["findings"][0], sidecar["checks"][0]
    if change == "claim":
        finding["hypothesis"] = "Different claim"
    elif change == "verdict":
        finding["status"] = "finding"
    elif change == "duplicate_finding":
        graded["findings"].append(deepcopy(finding))
    elif change == "duplicate_check":
        sidecar["checks"].append(deepcopy(check))
    elif change == "check_scope":
        check["scope"]["line_start"] = 20
    elif change == "claim_flag":
        finding["verification_trace"]["check_results"]["references"][0]["matches_final_claim"] = False
    else:
        finding["verification_trace"]["check_results"]["artifact"] = "../other/verification-checks.json"
    _save(tmp_path, graded, sidecar)
    rows = [_row()]
    verification.annotate_verification(rows, [_label()], tmp_path)
    assert rows[0]["verification"]["status"] == "unavailable"
    assert rows[0]["actual"] == "suspicious"


@pytest.mark.parametrize("failure", ["missing", "malformed", "oversized", "symlink"])
def test_unreadable_artifacts_do_not_change_results(tmp_path, monkeypatch, failure):
    _artifacts(tmp_path)
    path = tmp_path / "findings-graded.json"
    if failure == "missing":
        path.unlink()
    elif failure == "malformed":
        path.write_text("{")
    elif failure == "oversized":
        monkeypatch.setattr(verification, "_MAX_ARTIFACT_BYTES", 10)
    else:
        target = tmp_path / "target.json"
        path.rename(target)
        path.symlink_to(target)
    rows = [_row()]
    verification.annotate_verification(rows, [_label()], tmp_path)
    assert rows[0]["verification"]["status"] == "unavailable"
    assert rows[0]["match"] is True


def test_clean_unexported_label_does_not_inherit_a_claim(tmp_path):
    _artifacts(tmp_path)
    rows = [_row(actual="clean")]
    verification.annotate_verification(rows, [_label()], tmp_path)
    assert rows[0]["verification"]["status"] == "unavailable"
    assert rows[0]["actual"] == "clean"


@pytest.mark.parametrize("field", ["finding_id", "reference_extra", "trace_status"])
def test_untrusted_artifact_fields_cannot_poison_results_json(tmp_path, field):
    graded, sidecar = _artifacts(tmp_path)
    finding = graded["findings"][0]
    if field == "finding_id":
        finding["id"] = float("nan")
    elif field == "reference_extra":
        finding["verification_trace"]["check_results"]["references"][0]["untrusted"] = float("nan")
    else:
        finding["verification_trace"]["check_results"]["status"] = float("nan")
    _save(tmp_path, graded, sidecar)
    rows = [_row()]
    verification.annotate_verification(rows, [_label()], tmp_path)
    dumps_artifact(rows)
    assert rows[0]["actual"] == "suspicious"


def test_runner_checkpoint_retains_snapshot_without_rereading_artifacts(tmp_path, monkeypatch):
    audit = tmp_path / "audit"
    _artifacts(audit)
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.c").write_text("int f(void) { return 0; }\n")
    outcome = {"status": "suspicious", "hypothesis": "Fixture claim"}
    monkeypatch.setattr(runner, "_run_audit_on_target", lambda *a, **kw: ({"a.c:f": outcome}, {}, audit))
    checkpoint = tmp_path / "checkpoint.json"
    rows, _ = runner._run_audit([_label()], {"fixture": source}, checkpoint=checkpoint)
    assert rows[0]["verification"]["status"] == "recorded"
    (audit / "findings-graded.json").unlink()
    monkeypatch.setattr(runner, "_run_audit_on_target", lambda *a, **kw: pytest.fail("completed group reran"))
    resumed, _ = runner._run_audit([_label()], {"fixture": source}, checkpoint=checkpoint)
    assert resumed == rows


def test_splicing_preserves_prior_snapshot_and_uses_replacement_snapshot(tmp_path):
    saved = _row("a.c:kept")
    saved["verification"] = {"status": "recorded", "audit_dir": "/prior/audit"}
    replaced = _row("a.c:replaced")
    replaced["verification"] = {"status": "recorded", "audit_dir": "/old/audit"}
    path = tmp_path / "prior.json"
    path.write_text(json.dumps({"meta": {"count": 2}, "results": [saved, replaced]}))
    fresh = _row("a.c:replaced")
    fresh["verification"] = verification.unavailable_verification()
    merged, _ = runner._splice_results([fresh], path)
    by_id = {row["function_id"]: row for row in merged}
    assert by_id["a.c:kept"]["verification"] == saved["verification"]
    assert by_id["a.c:replaced"]["verification"] == fresh["verification"]
