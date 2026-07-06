from packages.web.evidence import build_web_evidence_ledger
from packages.web.models import WebFinding


def test_evidence_ledger_keeps_baseline_attack_diff_and_external_match():
    finding = WebFinding(
        id="WEB-0001",
        title="SQL Injection",
        severity="high",
        confidence="medium",
        status="needs_review",
        url="https://example.test/search",
        evidence="confirmed",
        description="SQLi",
        recommendation="Use parameters",
        vuln_type="injection",
        asvs_category="V5",
        check_id="V5.2.1",
        confirmed=True,
        target_url="https://example.test/search",
        confirmation_payload="' OR 1=1--",
        baseline_evidence="HTTP 200, 10 bytes",
        attack_evidence="SQL syntax error",
        diff_summary="baseline HTTP 200/10 bytes; attack HTTP 500/50 bytes",
        oracle_signal="sqli_error:sql syntax",
        affected_parameters=["q"],
        method="GET",
    )

    ledger = build_web_evidence_ledger(
        findings=[finding],
        request_history=[{"method": "GET"}],
        external_validation=[{
            "tool": "nuclei",
            "target_url": "https://example.test/search",
            "status": "matched",
        }],
        execution_policy={"scope_receipt": {"id": "receipt"}},
    )

    record = ledger["findings"][0]
    assert ledger["summary"]["confirmed_web_oracle_findings"] == 1
    assert [item["kind"] for item in record["proof_chain"]] == [
        "baseline_response",
        "attack_response",
        "response_diff",
        "oracle_signal",
    ]
    assert record["external_validation"][0]["tool"] == "nuclei"
    assert record["replay"]["parameters"] == ["q"]

