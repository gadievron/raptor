"""The actual publication seam emits shadow metadata without changing verdicts."""
from copy import deepcopy

from core.audit import check_trace
from core.audit.findings_export import write_graded_findings
from core.json import loads


def test_actual_publisher_preserves_legacy_projection(tmp_path, monkeypatch):
    monkeypatch.setattr(check_trace, "load_verified_audit_log", lambda _: [])
    finding = {"file": "a", "function": "f", "line": 1, "hypothesis": "claim",
               "status": "finding", "confidence": "high", "evidence_chain": ["legacy-strong"]}
    export = {"findings": [deepcopy(finding)], "stats": {}}
    write_graded_findings(export, tmp_path)
    assert export["findings"] == [finding]
    shadow = loads((tmp_path / "claim-adjudication-shadow.json").read_text())
    assert shadow["authoritative"] is False
    assert shadow["claims"] == []
    assert shadow["unmatched_legacy_findings"] == 1
    assert export["claim_adjudication_shadow"]["mode"] == "shadow"


def test_shadow_never_promotes_a_legacy_strong_chain():
    from core.audit.claim_adjudication import publication_shadow
    index = {"claims": [{"claim_reference": {"claim_id": "c", "revision_id": "r"},
                          "definition": {"file": "a", "function": "f", "line_start": 1},
                          "producer_check_ids": ["strong-check"]}]}
    findings = [{"file": "a", "function": "f", "line": 1,
                 "status": "finding", "confidence": "high"}]
    shadow = publication_shadow(index, findings)
    assert shadow["claims"][0]["state"] == "unresolved"
    assert shadow["claims"][0]["legacy_correspondence"] == "location_only_not_claim_authority"
    assert findings[0]["confidence"] == "high"
