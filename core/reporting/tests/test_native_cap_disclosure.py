"""A capped native table must not promise retention of independent input rows."""
from copy import deepcopy

from core.reporting import results
from core.reporting.renderers import render_document


def test_native_cap_does_not_claim_unembedded_rows_were_retained(monkeypatch):
    monkeypatch.setattr(results, "MAX_FINDINGS", 2)
    findings = [{"id": str(index), "title": f"captured-{index}"} for index in range(3)]
    original = deepcopy(findings)
    context, document = results.NativeResult("fixture", "captured", "one", {"metadata_only": True},
                                             findings=findings).build()
    assert len(context.findings) == 2
    assert context.extensions["raptor.accounting"]["recorded_findings"] == 3
    assert context.extensions["raptor.result"] == {"metadata_only": True}
    assert findings == original
    assert "complete domain payload retained" not in " ".join(context.diagnostics)
    rendered = render_document(document).content.decode()
    assert "2 of 3" in rendered and "unless supplied separately" in rendered


def test_native_cap_preserves_full_payload_when_producer_supplies_it(monkeypatch):
    monkeypatch.setattr(results, "MAX_FINDINGS", 2)
    findings = [{"id": str(index), "title": f"captured-{index}"} for index in range(3)]
    payload = {"findings": findings}
    original = deepcopy(payload)
    context, document = results.NativeResult("fixture", "captured", "one", payload, findings=findings).build()
    assert len(context.findings) == 2
    assert context.extensions["raptor.result"] == original
    assert context.extensions["raptor.result"]["findings"][2]["title"] == "captured-2"
    assert payload == original
    assert context.snapshot_id == document.snapshot_id
    assert "unless supplied separately" in " ".join(context.diagnostics)
