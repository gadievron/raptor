"""Oracle-proof gating of web findings into verified-outcome memory."""

from __future__ import annotations

from packages.web.attempts import build_attempt_from_confirmed_finding
from packages.web.models import WebFinding
from packages.web.verified_outcomes import (
    from_web_finding,
    verified_outcomes_for_findings,
)


def _oracle_proven_finding(**overrides) -> WebFinding:
    kwargs = dict(
        id="WEB-0001",
        title="SQL Injection",
        severity="high",
        confidence="medium",
        status="needs_review",
        url="https://example.test/search",
        evidence="confirmed",
        description="SQLi",
        recommendation="Use parameterised queries",
        vuln_type="sqli",
        asvs_category="V5",
        check_id="V5.2.1",
        cwe_id="CWE-89",
        confirmed=True,
        target_url="https://example.test/search",
        confirmation_payload="' OR 1=1--",
        response_evidence="SQL syntax",
        baseline_evidence="HTTP 200, 10 bytes",
        attack_evidence="SQL syntax",
        diff_summary="baseline HTTP 200/10 bytes; attack HTTP 500/50 bytes",
        attack_vector="query_param",
        oracle_signal="sqli_error:sql syntax",
        method="GET",
        affected_parameters=["q"],
    )
    kwargs.update(overrides)
    return WebFinding(**kwargs)


def test_web_finding_maps_to_verified_outcome():
    outcome = from_web_finding(_oracle_proven_finding())

    assert outcome is not None
    data = outcome.to_dict()
    assert data["oracle"] == "web"
    assert data["status"] == "verified"
    assert data["reproducible"] is False
    assert data["evidence"]["payload"] == "' OR 1=1--"
    assert data["evidence"]["diff_summary"].startswith("baseline HTTP")
    assert data["evidence"]["oracle_signal"] == "sqli_error:sql syntax"
    assert data["cwe_id"] == "CWE-89"


def test_passive_confirmed_web_finding_does_not_become_verified_outcome():
    finding = WebFinding(
        id="WEB-0002",
        title="Missing Content-Security-Policy",
        severity="medium",
        confidence="high",
        status="confirmed",
        url="https://example.test/",
        evidence="CSP header missing",
        description="No CSP header was observed",
        recommendation="Set a CSP header",
        vuln_type="missing_security_header",
        asvs_category="V14.4",
        check_id="V14.4.1",
        confirmed=True,
        target_url="https://example.test/",
    )

    assert from_web_finding(finding) is None
    assert build_attempt_from_confirmed_finding(finding) is None


def test_confirmed_finding_without_oracle_signal_is_not_promoted():
    finding = _oracle_proven_finding(oracle_signal=None)

    assert from_web_finding(finding) is None
    assert build_attempt_from_confirmed_finding(finding) is None


def test_confirmed_finding_without_cwe_is_not_promoted():
    finding = _oracle_proven_finding(cwe_id=None)

    assert from_web_finding(finding) is None


def test_batch_adapter_filters_unproven_findings():
    proven = _oracle_proven_finding()
    unproven = _oracle_proven_finding(id="WEB-0009", confirmation_payload=None)

    outcomes = verified_outcomes_for_findings([proven, unproven])

    assert [o.finding_id for o in outcomes] == ["WEB-0001"]


def test_confirmed_finding_builds_success_labeled_attempt(tmp_path):
    from core.labeled_attempts import collect_outcomes
    from packages.web.attempts import write_web_attempts

    finding = _oracle_proven_finding()
    attempt = build_attempt_from_confirmed_finding(finding)

    assert attempt is not None
    assert attempt.outcome == "success"
    assert attempt.cwe == "CWE-89"
    assert attempt.oracle == "web"
    assert attempt.reproducible is False
    assert attempt.web_evidence is not None
    assert attempt.web_evidence.http_request["param"] == "q"
    assert (
        attempt.web_evidence.response_evidence["oracle_signal"]
        == "sqli_error:sql syntax"
    )

    # Round-trip through the store: raptor-verified-outcomes' collection
    # path projects it as a VERIFIED web outcome.
    written = write_web_attempts([attempt], tmp_path)
    assert written
    outcomes = collect_outcomes(tmp_path)
    assert any(
        o.finding_id == attempt.finding_id and o.status.value == "verified"
        for o in outcomes
    )


def test_attempt_builder_redacts_secret_urls():
    finding = _oracle_proven_finding(
        target_url="https://example.test/search?api_key=sk-super-secret-123",
    )

    attempt = build_attempt_from_confirmed_finding(finding)

    assert attempt is not None
    assert "sk-super-secret-123" not in attempt.web_evidence.target_url
