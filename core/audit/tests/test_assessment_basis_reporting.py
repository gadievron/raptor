"""Journal consumer controls for descriptive basis, never model execution proof.

The positive row is an explicitly recorded consumer fixture with measured owned
source. Actual model invocation and producer wiring have a separate SDK control.
"""
from copy import deepcopy
from dataclasses import replace
import json
import shutil
from uuid import uuid4

import pytest

from core.audit.assessment_basis import record_assessment_basis
from core.audit.assessment_basis_reporting import (
    MAX_DISPLAYED, ROLE, assessment_basis_blocks, assessment_basis_summary,
    journal_assessment_basis,
)
from core.audit.collector import append_journal_for_outcome
from core.audit.journal import JOURNAL_FILENAME, append_entry, load_entries
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.orchestrator import ReviewOutcome
from core.audit.refutation_source import capture_source_identity
from core.audit.review_claims import begin_review, merge_history
from core.audit.verification_results import ReviewPublicationScope
from core.coverage import journal_mac
from core.reporting.document import ReportDocument
from core.reporting.renderers import get_renderer


@pytest.fixture
def recorded(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private"))
    target, out = tmp_path / "target", tmp_path / "original" / "run"
    target.mkdir()
    out.mkdir(parents=True)
    (target / "owned.c").write_text("unsigned f(unsigned n) { return n; }\n")
    (target / "other.c").write_text("unsigned other(unsigned n) { return n + 1; }\n")
    source = capture_source_identity(target, "owned.c")
    assert source is not None
    origin = KnowledgeOrigin(uuid4().hex, "owned.c", "f", 1, 1, source)
    attempt_id = uuid4().hex
    history = record_assessment_basis(begin_review(origin, attempt_id),
        origin=origin, attempt_id=attempt_id, status="clean")
    assert history is not None
    outcome = ReviewOutcome(file="owned.c", function="f", line=1, status="clean",
        body="Descriptive journal consumer fixture", review_result={"review_claims": history})
    ack = append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name,
        outcome=outcome, gap={"file": "owned.c", "name": "f", "line_start": 1, "line_end": 1},
        publication_scope=ReviewPublicationScope("owned.c", "f", 1, 1, source))
    assert ack is not None
    entry, = load_entries(out, fresh=True)
    assert journal_mac.entry_provenance(entry) == journal_mac.ROW_VERIFIED
    return target, out, origin, entry


def test_original_owned_journal_basis_is_historical_without_changing_assessment(recorded):
    _, out, origin, entry = recorded
    before = (entry.verdict, entry.source_hash, entry.evidence_tools, deepcopy(entry.review_claims))
    basis = journal_assessment_basis(entry, out)
    assert basis is not None and basis["basis"] == "model_judgment"
    assert basis["pass_id"] == origin.pass_id and basis["status"] == "clean"
    assert basis["scope"] == "historical_review_only"
    assert "assurance" not in basis and "verified" not in basis
    assert (entry.verdict, entry.source_hash, entry.evidence_tools, entry.review_claims) == before


@pytest.mark.parametrize("fault", ["status", "file", "function", "line_start", "line_end", "source",
                                  "mechanical", "other_producer", "legacy", "top_only", "mixed",
                                  "unknown_origin", "unknown_source", "gate_resolved"])
def test_signed_record_with_wrong_binding_or_missing_attribution_is_unavailable(recorded, tmp_path, fault):
    target, _, origin, entry = recorded
    changes = {}
    if fault == "status":
        changes["verdict"] = "suspicious"
    elif fault == "file":
        changes["file"] = "other.c"
    elif fault == "function":
        changes["function"] = "other"
    elif fault == "line_start":
        changes.update(line_start=2, line_end=2)
    elif fault == "line_end":
        changes["line_end"] = 2
    elif fault == "source":
        other = capture_source_identity(target, "other.c")
        assert other is not None and other.sha256 != origin.source_identity.sha256
        changes["source_hash"] = entry.source_hash.replace(origin.source_identity.sha256, other.sha256)
        assert changes["source_hash"] != entry.source_hash
    elif fault == "mechanical":
        changes["strategies"] = ["post-loop-mechanical"]
    elif fault == "other_producer":
        changes["producer"] = "agentic"
    elif fault == "gate_resolved":
        # Signed classification fixture, not proof a gate actually resolved.
        # A descriptive model label must not replace this distinct clean basis.
        changes["clean_basis"] = "gate_resolved"
    elif fault == "legacy":
        changes["review_claims"] = None
    elif fault == "top_only":
        history = begin_review(origin, uuid4().hex)
        history["assessment_basis"] = "model_judgment_withdrawal"
        history["withdrawal_decisions"] = {"admissible": True}
        changes["review_claims"] = history
    elif fault == "mixed":
        other_origin = replace(origin, pass_id=uuid4().hex)
        changes["review_claims"] = merge_history(entry.review_claims, begin_review(other_origin, uuid4().hex))
    elif fault in {"unknown_origin", "unknown_source"}:
        history = deepcopy(entry.review_claims)
        bound_origin = history["review"]["origin"]
        if fault == "unknown_origin":
            bound_origin["assurance"] = "verified"
        else:
            bound_origin["source_identity"]["build_closure"] = "claimed-complete"
        changes["review_claims"] = history
    # A real writer supplies a valid MAC for deliberately inconsistent
    # consumer input. Integrity alone must not repair its interpretation.
    destination = tmp_path / fault / "run"
    destination.mkdir(parents=True)
    append_entry(destination, replace(entry, **changes))
    loaded, = load_entries(destination, fresh=True)
    assert journal_mac.entry_provenance(loaded) == journal_mac.ROW_VERIFIED
    assert loaded.run_path == str(destination.resolve()) and loaded.run_id == destination.name
    assert journal_assessment_basis(loaded, destination) is None


def test_same_basename_foreign_run_copy_cannot_borrow_basis(recorded, tmp_path):
    _, original, _, _ = recorded
    foreign = tmp_path / "foreign" / original.name
    foreign.mkdir(parents=True)
    shutil.copy2(original / JOURNAL_FILENAME, foreign / JOURNAL_FILENAME)
    loaded, = load_entries(foreign, fresh=True)
    assert loaded.run_id == foreign.name
    assert loaded.run_path == str(original.resolve()) != str(foreign.resolve())
    assert journal_assessment_basis(loaded, foreign) is None


def test_tampered_basis_row_is_not_a_recorded_judgment(recorded):
    _, out, _, _ = recorded
    path = out / JOURNAL_FILENAME
    row = json.loads(path.read_text().splitlines()[0])
    row["review_claims"]["review"]["assessment_status"] = "suspicious"
    path.write_text(json.dumps(row) + "\n")
    loaded, = load_entries(out, fresh=True)
    assert journal_mac.entry_provenance(loaded) != journal_mac.ROW_VERIFIED
    assert journal_assessment_basis(loaded, out) is None


def test_unstamped_row_cannot_issue_basis(recorded):
    _, out, _, _ = recorded
    path = out / JOURNAL_FILENAME
    row = json.loads(path.read_text().splitlines()[0])
    row.pop("integrity", None)
    path.write_text(json.dumps(row) + "\n")
    loaded, = load_entries(out, fresh=True)
    assert journal_mac.entry_provenance(loaded) != journal_mac.ROW_VERIFIED
    assert journal_assessment_basis(loaded, out) is None


def test_summary_bounds_display_and_counts_unknown_without_mutating_inputs(recorded):
    _, out, _, entry = recorded
    basis = journal_assessment_basis(entry, out)
    assert basis is not None
    rows = [{"file": "owned.c", "function": "f", "line_start": 1, "status": "clean",
             "assessment_basis": basis}]
    rows.extend({"file": f"unknown-{index}.c", "function": "f", "line_start": 1,
                 "status": "suspicious"} for index in range(MAX_DISPLAYED + 2))
    rows.append({"file": "mechanical.c", "function": "f", "line_start": 1,
                 "status": "finding", "mechanical": True})
    before = deepcopy(rows)
    summary = assessment_basis_summary({"functions_analysed": rows})
    assert summary["role"] == ROLE
    assert summary["recorded"] == 1 and summary["unavailable"] == MAX_DISPLAYED + 2
    assert len(summary["records"]) == MAX_DISPLAYED and summary["records_omitted"] == 3
    assert summary["records"][0]["basis"] == "model_judgment"
    assert all(row["basis"] == "unavailable" for row in summary["records"][1:])
    assert rows == before
    assert [row["status"] for row in rows] == [row["status"] for row in before]


def test_empty_or_only_mechanical_records_do_not_invent_basis():
    assert assessment_basis_summary({"functions_analysed": []}) is None
    assert assessment_basis_summary({"functions_analysed": [{"mechanical": True}]}) is None


@pytest.mark.parametrize("change", [
    {"role": "authoritative"}, {"recorded": True}, {"unavailable": -1}, {"records": "wrong"},
])
def test_invalid_summary_cannot_render_an_assurance_label(change):
    summary = {"role": ROLE, "recorded": 0, "unavailable": 0, "records": [], "records_omitted": 0}
    summary.update(change)
    blocks = assessment_basis_blocks({"assessment_bases": summary})
    assert len(blocks) == 1 and blocks[0].title == "Recorded reviewer basis unavailable"
    assert "no assurance is inferred" in blocks[0].text


def test_unknown_basis_label_cannot_render_mechanical_assurance():
    record = {"file": "owned.c", "function": "f", "line_start": 1, "status": "clean",
              "basis": "mechanically_verified", "scope": "historical_review_only"}
    blocks = assessment_basis_blocks({"assessment_bases": {"role": ROLE, "recorded": 1,
        "unavailable": 0, "records": [record], "records_omitted": 0}})
    assert blocks[0].title == "Recorded reviewer basis unavailable"
    assert all(not block.rows for block in blocks)


def test_recorded_unit_fields_are_escaped_by_the_actual_portable_renderer():
    record = {"file": "a|<img src=x>.c", "function": "f\n# injected heading", "line_start": 1,
              "status": "clean", "basis": "model_judgment", "scope": "historical_review_only"}
    blocks = assessment_basis_blocks({"assessment_bases": {"role": ROLE, "recorded": 1,
        "unavailable": 0, "records": [record], "records_omitted": 0}})
    document = ReportDocument("Consumer fixture", "audit", "consumer-fixture", blocks=blocks)
    markdown = get_renderer("markdown").render(document).content.decode()
    assert "Recorded reviewer basis" in markdown and "Model judgement" in markdown
    assert "does not establish" in markdown and "mechanical assurance" in markdown
    assert "\n# injected heading" not in markdown
    assert "<img src=x>" not in markdown
    assert "a&#124;" in markdown
