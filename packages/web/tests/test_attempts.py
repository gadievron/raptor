"""web_evidence LabeledAttempt production, projection into
raptor-verified-outcomes, and the scanner's Phase 2.5 wiring."""

from __future__ import annotations

import pytest

pytest.importorskip("requests")

from core.labeled_attempts.store import read_all  # noqa: E402
from core.labeled_attempts.view import (  # noqa: E402
    Oracle,
    OutcomeStatus,
    collect_outcomes,
    from_labeled_attempt,
)
from packages.web.attempts import (  # noqa: E402
    build_web_attempt,
    write_web_attempts,
)
from packages.web.oracle import (  # noqa: E402
    INCONCLUSIVE,
    REFUTED,
    VERIFIED,
    VerificationResult,
)


def _result(status, refuted_by_control=False):
    return VerificationResult(
        status=status,
        evidence_type="sqli_error",
        requests_used=3,
        observations={"marker_on_replay": status == VERIFIED},
        refuted_by_control=refuted_by_control,
        reason="test",
    )


def _attempt(status, refuted_by_control=False, **kw):
    args = dict(
        url="http://target.example/search?x=1",
        param="q",
        payload="' OR 1=1--",
        vuln_type="sqli",
        method="GET",
        result=_result(status, refuted_by_control),
    )
    args.update(kw)
    return build_web_attempt(**args)


class TestBuildWebAttempt:
    def test_verified_record_shape(self):
        la = _attempt(VERIFIED)
        assert la.outcome == "success"
        assert la.cwe == "CWE-89"
        assert la.web_evidence is not None
        assert la.web_evidence.evidence_type == "sqli_error"
        assert la.reproducible is False
        assert la.oracle == "web"
        int(la.finding_signature, 16)  # hex signature

    def test_cwe_map(self):
        for vt, cwe in (("xss", "CWE-79"), ("command_injection", "CWE-78"),
                        ("path_traversal", "CWE-22")):
            assert _attempt(VERIFIED, vuln_type=vt).cwe == cwe

    def test_refuted_carries_control_flag(self):
        la = _attempt(REFUTED, refuted_by_control=True)
        assert la.outcome == "reasoned_failure"
        assert la.web_evidence.response_evidence["refuted_by_control"] is True

    def test_inconclusive_is_uncertain(self):
        la = _attempt(INCONCLUSIVE)
        assert la.outcome == "uncertain"
        assert "refuted_by_control" not in la.web_evidence.response_evidence

    def test_url_credentials_redacted(self):
        la = _attempt(VERIFIED, url="http://user:hunter2@target.example/s")
        assert "hunter2" not in la.web_evidence.target_url
        assert "hunter2" not in str(la.web_evidence.http_request)

    def test_signature_stable_across_query_noise(self):
        a = _attempt(VERIFIED, url="http://t.example/api?id=1")
        b = _attempt(REFUTED, url="http://t.example/api?id=999",
                     refuted_by_control=True)
        assert a.finding_signature == b.finding_signature


class TestProjection:
    def test_verified_projects_verified(self):
        vo = from_labeled_attempt(_attempt(VERIFIED))
        assert vo.oracle == Oracle.WEB
        assert vo.status == OutcomeStatus.VERIFIED
        assert vo.reproducible is False

    def test_control_refuted_projects_refuted(self):
        vo = from_labeled_attempt(_attempt(REFUTED, refuted_by_control=True))
        assert vo.status == OutcomeStatus.REFUTED

    def test_reasoned_failure_without_control_flag_stays_inconclusive(self):
        # A failed attempt with no positive control evidence must not
        # over-claim REFUTED — mirrors the CodeQL is_sound gate.
        la = _attempt(REFUTED, refuted_by_control=False)
        assert la.outcome == "reasoned_failure"
        vo = from_labeled_attempt(la)
        assert vo.status == OutcomeStatus.INCONCLUSIVE

    def test_uncertain_projects_inconclusive(self):
        vo = from_labeled_attempt(_attempt(INCONCLUSIVE))
        assert vo.status == OutcomeStatus.INCONCLUSIVE


class TestStoreRoundTrip:
    def test_write_and_collect_from_run_dir(self, tmp_path):
        attempts = [
            _attempt(VERIFIED),
            _attempt(REFUTED, refuted_by_control=True, vuln_type="xss"),
        ]
        written = write_web_attempts(attempts, tmp_path)
        assert len(written) == 2
        assert all(p.is_relative_to(tmp_path / "labeled_attempts")
                   for p in written)

        stored = list(read_all(project_dir=tmp_path, include_global=False))
        assert len(stored) == 2

        # collect_outcomes reads the run dir's own pool.
        outcomes = [o for o in collect_outcomes(tmp_path)
                    if o.oracle == Oracle.WEB]
        statuses = sorted(o.status for o in outcomes)
        assert statuses == sorted(
            [OutcomeStatus.VERIFIED, OutcomeStatus.REFUTED])

    def test_collect_does_not_double_read_same_pool(self, tmp_path):
        write_web_attempts([_attempt(VERIFIED)], tmp_path)
        outcomes = [o for o in collect_outcomes(tmp_path, project_root=tmp_path)
                    if o.oracle == Oracle.WEB]
        assert len(outcomes) == 1

    def test_write_failure_is_soft(self, tmp_path, monkeypatch):
        import packages.web.attempts as attempts_mod

        def boom(*a, **kw):
            raise OSError("disk full")

        monkeypatch.setattr(attempts_mod, "store_write", boom)
        assert write_web_attempts([_attempt(VERIFIED)], tmp_path) == []


class _StubOracle:
    def __init__(self, client):
        self.requests_used = 0
        self.errors = 0

    def verify(self, url, param, payload, vuln_type, method="GET"):
        self.requests_used += 3
        return _result(VERIFIED)


class TestScannerWiring:
    def _scanner(self, tmp_path, monkeypatch, cap=25):
        import packages.web.oracle as oracle_mod
        from packages.web.scanner import WebScanner

        monkeypatch.setattr(oracle_mod, "VerificationOracle", _StubOracle)
        scanner = object.__new__(WebScanner)
        scanner.out_dir = tmp_path
        scanner.verify_findings = True
        scanner.max_verifications = cap
        scanner.reveal_secrets = False
        scanner.client = object()
        return scanner

    def _finding(self, i=0):
        return {
            "url": "http://t.example/s",
            "parameter": "q",
            "payload": f"' OR {i}={i}--",
            "vulnerability_type": "sqli",
            "status_code": 200,
            "response_length": 10,
        }

    def test_findings_annotated_and_records_written(self, tmp_path, monkeypatch):
        scanner = self._scanner(tmp_path, monkeypatch)
        f = self._finding()
        summary = scanner._verify_findings(
            [(f, "http://t.example/s", "q", "GET")])
        assert f["verification"]["status"] == VERIFIED
        assert summary["verified"] == 1
        assert summary["records_written"] == 1
        assert (tmp_path / "labeled_attempts").is_dir()

    def test_cap_marks_overflow_skipped_and_keeps_findings(
            self, tmp_path, monkeypatch):
        scanner = self._scanner(tmp_path, monkeypatch, cap=1)
        findings = [self._finding(i) for i in range(3)]
        contexts = [(f, "http://t.example/s", "q", "GET") for f in findings]
        summary = scanner._verify_findings(contexts)
        assert summary["verified"] == 1
        assert summary["skipped"] == 2
        assert all("verification" in f for f in findings)
        assert [f["verification"]["status"] for f in findings] == [
            VERIFIED, "skipped", "skipped"]
