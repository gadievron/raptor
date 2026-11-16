"""Captured normal publication reaches typed shadow presentation, not authority."""
import copy
import json

from core.audit import check_trace
from core.audit.claims import ClaimRevision
from core.audit.claim_verification import ClaimVerification
from core.audit.findings_export import export_findings, write_graded_findings
from core.audit.orchestrator import ReviewOutcome
from core.audit.report import generate_report
from core.audit.report_document import build_audit_document
from core.reporting.renderers import get_renderer


def test_actual_publisher_shadow_reaches_json_and_markdown_without_upgrading(tmp_path):
    hypothesis = {"mechanism": "Captured unresolved concern"}
    revision = ClaimRevision(hypothesis, pass_id="captured-pass", file="owned.c", function="f", line_start=1)
    check_trace.record_claim_observations(tmp_path, file="owned.c", function="f", line_start=1,
                                         verifications=[ClaimVerification(hypothesis, claim_revision=revision)])
    outcome = ReviewOutcome(file="owned.c", function="f", line=1, status="suspicious",
                            body="Captured review judgment", hypothesis=hypothesis["mechanism"])
    graded = export_findings([outcome])
    before = copy.deepcopy(graded)
    write_graded_findings(graded, tmp_path)
    # The headline report consumes its separate native findings file.
    (tmp_path / "findings.json").write_text(json.dumps(graded["findings"]), encoding="utf-8")
    report = generate_report(tmp_path)
    shadow = report["claim_adjudication"]
    assert shadow["mode"] == "shadow" and shadow["authoritative"] is False
    row, = shadow["claims"]
    assert row["claim_id"] == revision.claim_id and row["state"] == "unresolved"
    assert "assessment_basis" not in row and "assurance" not in row
    # The normal publisher adds trace links. Assessment fields must stay
    # unchanged while that additional provenance reaches the report.
    for key in ("status", "confidence", "verification_tier", "hypothesis"):
        assert report["findings"][0][key] == before["findings"][0][key]
        assert graded["findings"][0][key] == before["findings"][0][key]
    assert outcome.status == "suspicious"
    assert report["findings"][0]["discovery"]["confirmed_by"] == []
    context, document = build_audit_document(report, tmp_path)
    titles = [block.title for block in document.blocks]
    assert titles.index("Findings") < titles.index("Claim adjudication (shadow; not authoritative)")
    for fmt in ("json", "markdown"):
        rendered = get_renderer(fmt).render(document).content.decode()
        (tmp_path / ("rendered-report." + fmt)).write_text(rendered, encoding="utf-8")
        assert "unresolved" in rendered
        assert "Assessment basis and assurance grade were not recorded" in rendered
        assert "Shadow comparison only" in rendered
        assert "not replace legacy assessments" in rendered
        assert "no current finding was established" in rendered
        assert "not safety conclusions" in rendered
        assert "registered whole claim contract and current admission unavailable" in rendered
    assert any(item["path"] == str(tmp_path / "claim-adjudication-shadow.json") for item in context.artifacts)


def test_missing_shadow_retains_legacy_projection(tmp_path):
    outcome = ReviewOutcome(file="owned.c", function="f", line=1, status="suspicious",
                            body="Captured prior judgment", hypothesis="Captured prior concern")
    findings = export_findings([outcome])["findings"]
    (tmp_path / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    report = generate_report(tmp_path)
    assert report["claim_adjudication"]["mode"] == "unavailable"
    assert report["claim_adjudication"]["authoritative"] is False
    assert report["claim_adjudication"]["artifact"] is None
    assert report["findings"][0]["status"] == findings[0]["status"] == "suspicious"
    assert report["findings"][0]["confidence"] == findings[0]["confidence"]
    context, document = build_audit_document(report, tmp_path)
    assert all("claim-adjudication-shadow.json" not in item["path"] for item in context.artifacts)
    markdown = get_renderer("markdown").render(document).content.decode()
    assert "Claim adjudication unavailable" in markdown and "legacy assessments are unchanged" in markdown


def test_authoritative_flag_cannot_activate_consumer_switch(tmp_path):
    (tmp_path / "claim-adjudication-shadow.json").write_text(json.dumps({
        "schema_version": 1, "mode": "shadow", "authoritative": True,
        "policy_version": "claim-adjudication-v1", "claims": [],
    }), encoding="utf-8")
    report = generate_report(tmp_path)
    assert report["claim_adjudication"]["mode"] == "unavailable"
    assert report["claim_adjudication"]["authoritative"] is False
    _, document = build_audit_document(report, tmp_path)
    assert "legacy assessments are unchanged" in get_renderer("markdown").render(document).content.decode()


def test_full_shadow_state_counts_survive_display_cap_in_actual_report(tmp_path):
    rows = [{"claim_id": f"claim-{i}", "revision_id": f"revision-{i}",
             "state": "unresolved" if i < 100 else "conflicted"}
            for i in range(103)]
    (tmp_path / "claim-adjudication-shadow.json").write_text(json.dumps({
        "schema_version": 1, "mode": "shadow", "authoritative": False,
        "policy_version": "claim-adjudication-v1", "claims": rows,
    }), encoding="utf-8")
    report = generate_report(tmp_path)
    shadow = report["claim_adjudication"]
    assert shadow["state_counts"]["unresolved"] == 100
    assert shadow["state_counts"]["conflicted"] == 3
    assert sum(shadow["state_counts"].values()) == shadow["claim_count"] == 103
    assert len(shadow["claims"]) == 100 and shadow["claims_omitted"] == 3
    assert shadow["authoritative"] is False
    _, document = build_audit_document(report, tmp_path)
    markdown = get_renderer("markdown").render(document).content.decode()
    assert "Recorded claim states" in markdown
    assert "conflicted" in markdown and "3" in markdown
    assert "Shadow comparison only" in markdown


def test_malformed_omitted_shadow_row_cannot_produce_complete_counts(tmp_path):
    rows = [{"claim_id": f"claim-{i}", "revision_id": f"revision-{i}", "state": "unresolved"}
            for i in range(100)] + [{"claim_id": "hidden", "revision_id": "bad", "state": "safe"}]
    (tmp_path / "claim-adjudication-shadow.json").write_text(json.dumps({
        "schema_version": 1, "mode": "shadow", "authoritative": False,
        "policy_version": "claim-adjudication-v1", "claims": rows,
    }), encoding="utf-8")
    report = generate_report(tmp_path)
    assert report["claim_adjudication"]["mode"] == "unavailable"
    assert "state_counts" not in report["claim_adjudication"]


def test_saved_shadow_report_without_totals_still_renders(tmp_path):
    (tmp_path / "claim-adjudication-shadow.json").write_text(json.dumps({
        "schema_version": 1, "mode": "shadow", "authoritative": False,
        "policy_version": "claim-adjudication-v1", "claims": [
            {"claim_id": "old-claim", "revision_id": "old-revision", "state": "unresolved"}],
    }), encoding="utf-8")
    report = generate_report(tmp_path)
    del report["claim_adjudication"]["state_counts"]  # Exact prior saved report shape.
    report["claim_adjudication"]["claim_count"] = 103
    report["claim_adjudication"]["claims_omitted"] = 102
    _, document = build_audit_document(report, tmp_path)
    markdown = get_renderer("markdown").render(document).content.decode()
    assert "Recorded claim-state totals are unavailable" in markdown
    assert "old-claim" in markdown and "unresolved" in markdown
    assert "Recorded claim states" not in markdown
    assert "Shadow comparison only" in markdown


# Reuse the actual local issuer/validator fixture; no provider or legacy engine.
from core.audit.tests.test_conditional_claim_pipeline import (  # noqa: E402
    declaration, intake, live, publish, review,  # noqa: F401, F811 -- pytest fixture
)


def test_conditional_publisher_reaches_report_with_all_conditions_without_promotion(live):  # noqa: F811 -- imported fixture
    from core.audit.conditional_member_policy import conclusion_signature
    review(live, [declaration()])
    intake(live)
    shadow = publish(live)
    before = copy.deepcopy(shadow)
    report = generate_report(live.out)
    evidence = report["claim_adjudication"]["conditional_evidence"]
    item, = evidence["records"]
    signature = conclusion_signature()
    assert item["conclusion"]["statement"] == signature.statement
    assert item["conclusion"]["conditions"] == list(signature.conditions)
    assert item["publication_reason"] == "retained-conditional-support"
    assert item["authoritative"] is False and item["issuer_cwe_verified"] is False
    assert report["findings"] == []
    _, document = build_audit_document(report, live.out)
    for fmt in ("json", "markdown"):
        rendered = get_renderer(fmt).render(document).content.decode()
        assert "Conditional evidence (recorded; not authoritative)" in rendered
        assert "does not revalidate current source" in rendered
        assert signature.statement in rendered
        for condition in signature.conditions:
            assert condition in rendered
    assert json.loads((live.out / "claim-adjudication-shadow.json").read_text()) == before
    # A later consumed publication must not resurrect the former support.
    publish(live)
    later = generate_report(live.out)
    assert all(row["publication_reason"] != "retained-conditional-support"
               for row in later["claim_adjudication"]["conditional_evidence"]["records"])


def test_malformed_conditional_details_preserve_ordinary_claim_states(tmp_path):
    from core.audit.claim_presentation import load_claim_presentation
    payload = {"schema_version": 1, "mode": "shadow", "authoritative": False,
               "policy_version": "recorded-policy", "claims": [
                   {"claim_id": "claim", "revision_id": "revision", "state": "unresolved"}],
               "preparation_availability": [{"claim_reference": {
                   "claim_id": "claim", "revision_id": "revision"},
                   "requested_conclusion": {"conditions": "untrusted"}}]}
    (tmp_path / "claim-adjudication-shadow.json").write_text(json.dumps(payload))
    projected = load_claim_presentation(tmp_path)
    assert projected["mode"] == "shadow"
    assert projected["state_counts"]["unresolved"] == 1
    assert projected["conditional_evidence"] == {"state": "unavailable", "records": []}


def test_stale_source_publication_cannot_display_retained_support(live):  # noqa: F811 -- imported fixture
    review(live, [declaration()])
    intake(live)
    path = live.root / "protocol/parser.c"
    path.write_text(path.read_text() + "\n/* source changed */\n")
    shadow = publish(live)
    assert not any(row["supported_obligations"] for row in shadow["claims"])
    report = generate_report(live.out)
    assert not any(row["publication_reason"] == "retained-conditional-support"
                   for row in report["claim_adjudication"]["conditional_evidence"]["records"])
    assert report["findings"] == []
