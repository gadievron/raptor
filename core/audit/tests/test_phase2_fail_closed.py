"""Phase-2 classification fail-closed contract.

A Phase-2 call that errors (expired auth token, transport failure,
provider outage) must record an "error" cell — never a
quality_finding default that the suppression loop would treat as a
live ruling and use to demote a true positive to clean.
"""

from unittest.mock import MagicMock, patch

import core.audit.corpus.run_corpus as rc


def _finding(fid="src/a.c:f", actual="suspicious", **extra):
    row = {
        "function_id": fid,
        "expected": "finding",
        "actual": actual,
        "hypothesis": "off-by-one in bounds check",
        "match": False,
    }
    row.update(extra)
    return row


def _client_raising(exc=RuntimeError("401 token expired")):
    client = MagicMock()
    client.config.config_for_model.side_effect = ValueError("no model")
    client.generate_structured.side_effect = exc
    return client


class TestPhase2FailClosed:
    def test_exception_records_error_not_quality(self):
        findings = [_finding()]
        with patch("core.llm.client.LLMClient",
                   return_value=_client_raising()):
            rc._run_phase2_classify(findings)
        r = findings[0]
        assert r["phase2_classification"] == "error"
        assert r["phase2_error"] is True
        assert r["phase2_is_security"] is False
        assert r["phase2_primitive"] == "none"

    def test_consecutive_failures_trip_circuit_breaker(self):
        n = rc._PHASE2_FAILURE_ABORT + 4
        findings = [_finding(fid=f"src/a.c:f{i}") for i in range(n)]
        client = _client_raising()
        with patch("core.llm.client.LLMClient", return_value=client):
            rc._run_phase2_classify(findings)
        # Only the first _PHASE2_FAILURE_ABORT calls hit the dead
        # route; the rest are marked errored without a call.
        assert client.generate_structured.call_count == \
            rc._PHASE2_FAILURE_ABORT
        assert all(r["phase2_classification"] == "error" for r in findings)
        assert all(r["phase2_error"] for r in findings)

    def test_success_resets_consecutive_failure_count(self):
        findings = [_finding(fid=f"src/a.c:f{i}") for i in range(6)]
        client = MagicMock()
        client.config.config_for_model.side_effect = ValueError("x")
        ok = MagicMock()
        ok.cost = 0.0
        # fail, fail, ok, fail, fail, ok — never 3 consecutive.
        client.generate_structured.side_effect = [
            RuntimeError("x"), RuntimeError("x"), ok,
            RuntimeError("x"), RuntimeError("x"), ok,
        ]
        with patch("core.llm.client.LLMClient", return_value=client), \
             patch.object(rc, "structured_result",
                          return_value={"classification": "security_finding",
                                        "is_security": True}):
            rc._run_phase2_classify(findings)
        assert client.generate_structured.call_count == 6
        errored = [r for r in findings if r.get("phase2_error")]
        assert len(errored) == 4

    def test_prompt_carries_counter_and_evidence(self):
        findings = [_finding(
            counter_hypothesis="callers hold the lock",
            evidence_tool="smt:check-toctou",
        )]
        client = MagicMock()
        client.config.config_for_model.side_effect = ValueError("x")
        ok = MagicMock()
        ok.cost = 0.0
        client.generate_structured.return_value = ok
        with patch("core.llm.client.LLMClient", return_value=client), \
             patch.object(rc, "structured_result",
                          return_value={"classification": "quality_finding",
                                        "is_security": False}):
            rc._run_phase2_classify(findings)
        prompt = client.generate_structured.call_args[0][0]
        assert "callers hold the lock" in prompt
        assert "smt:check-toctou" in prompt


class TestSuppressionExcludesErrors:
    def test_error_cell_never_demotes(self):
        rows = [_finding(
            phase2_classification="error",
            phase2_error=True,
            phase2_is_security=False,
            phase2_primitive="none",
        )]
        assert rc._suppress_quality_findings(rows) == 0
        assert rows[0]["actual"] == "suspicious"
        assert not rows[0].get("phase2_suppressed")

    def test_live_quality_ruling_still_demotes(self):
        rows = [_finding(
            phase2_classification="quality_finding",
            phase2_is_security=False,
            phase2_primitive="none",
            evidence_tool="llm-claimed:reasoning",
        )]
        assert rc._suppress_quality_findings(rows) == 1
        assert rows[0]["actual"] == "clean"
        assert rows[0]["phase2_suppressed"] is True

    def test_verification_evidence_still_shields(self):
        rows = [_finding(
            phase2_classification="quality_finding",
            phase2_is_security=False,
            phase2_primitive="none",
            evidence_tool="smt:counter-witness-verified",
        )]
        # _is_verification_evidence decides; this row carries a
        # verification-role receipt so it survives regardless.
        if rc._is_verification_evidence("smt:counter-witness-verified"):
            assert rc._suppress_quality_findings(rows) == 0
            assert rows[0]["actual"] == "suspicious"

    def test_missing_classification_never_demotes(self):
        # Outer Phase-2 failure path: no phase2_* keys at all.
        rows = [_finding()]
        assert rc._suppress_quality_findings(rows) == 0
        assert rows[0]["actual"] == "suspicious"


class TestSecurityClassifierFailClosed:
    def test_exception_records_error_classification(self, tmp_path):
        from types import SimpleNamespace

        from core.audit.security_classifier import classify_security_impact

        outcome = SimpleNamespace(
            file="src/a.c", function="f", status="suspicious",
            hypothesis="h", body="b", review_result={},
        )
        client = MagicMock()
        client.config.config_for_model.side_effect = ValueError("x")
        client.generate_structured.side_effect = RuntimeError("401")
        client.model_name = ""
        results = classify_security_impact([outcome], tmp_path, client)
        res = results["src/a.c:f"]
        assert res["classification"] == "error"
        assert res["is_security"] is False
