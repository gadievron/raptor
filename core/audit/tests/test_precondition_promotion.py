"""Tests for _promote_suspicious_preconditions — the suspicious→finding
promotion path driven by mechanical verification of LLM-stated
preconditions. No LLM calls; verify_preconditions is stubbed where the
orchestration logic (not the checkers) is under test."""

from __future__ import annotations

import json

from core.audit.precondition_check import CheckResult, PreconditionVerdict


def _verdict(*checks: tuple[str, str]) -> PreconditionVerdict:
    """Build a PreconditionVerdict from (check_type, verdict) pairs."""
    v = PreconditionVerdict()
    for check_type, res in checks:
        v.checks.append(CheckResult(
            check_type=check_type,
            assumption=f"assume {check_type}",
            verdict=res,
            evidence=f"evidence for {check_type}",
        ))
    return v


class TestPreconditionVerdictAggregates:
    def test_all_supported_true(self):
        v = _verdict(
            ("attacker_controls_input", "supported"),
            ("caller_bounds_checks", "supported"),
        )
        assert v.all_supported is True
        assert v.supported_types == frozenset(
            {"attacker_controls_input", "caller_bounds_checks"},
        )

    def test_all_supported_false_on_inconclusive(self):
        v = _verdict(
            ("attacker_controls_input", "supported"),
            ("caller_sanitizes", "inconclusive"),
        )
        assert v.all_supported is False

    def test_all_supported_false_on_empty(self):
        assert PreconditionVerdict().all_supported is False


class TestPreconditionReceiptGrading:
    def test_precondition_stamp_is_tool_evidence(self):
        from core.audit.evidence_grade import is_tool_evidence
        assert is_tool_evidence(
            "precondition:attacker_controls_input,caller_bounds_checks",
        )

    def test_precondition_receipt_grades_medium(self):
        from core.audit.evidence_grade import (
            Confidence,
            finding_confidence,
            grade_review_result,
        )
        items = grade_review_result(
            {"hypothesis": "stack overflow via unchecked memcpy"},
            "precondition:attacker_controls_input",
        )
        sources = {e.source.value for e in items}
        assert "mechanical:precondition" in sources
        assert finding_confidence(items) == Confidence.MEDIUM


class TestPromoteSuspiciousPreconditions:
    def _outcome(self, preconditions, status="suspicious", body="looks bad"):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="a.c", function="f", status=status,
            body=body, hypothesis="unchecked memcpy of attacker data",
            line=3,
        )
        o.review_result = {
            "hypothesis": o.hypothesis,
            "preconditions": preconditions,
        }
        return o

    def _preconditions(self, *check_types):
        return [
            {
                "assumption": f"assume {ct}",
                "check_type": ct,
                "location": {"file": "a.c", "function": "f"},
                "expect_absent": True,
            }
            for ct in check_types
        ]

    def _result(self, outcomes):
        from core.audit.orchestrator import OrchestratorResult
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
        r.findings = sum(1 for o in outcomes if o.status == "finding")
        r.clean = sum(1 for o in outcomes if o.status == "clean")
        return r

    def _config(self, tmp_path):
        from core.audit.orchestrator import OrchestratorConfig
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        return OrchestratorConfig(target_path=tmp_path, out_dir=out)

    def _patch_verdict(self, monkeypatch, verdict):
        monkeypatch.setattr(
            "core.audit.precondition_check.verify_preconditions",
            lambda *a, **kw: verdict,
        )

    def test_all_supported_with_load_bearing_promotes(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _promote_suspicious_preconditions,
        )
        outcome = self._outcome(self._preconditions(
            "attacker_controls_input", "caller_bounds_checks",
        ))
        result = self._result([outcome])
        self._patch_verdict(monkeypatch, _verdict(
            ("attacker_controls_input", "supported"),
            ("caller_bounds_checks", "supported"),
        ))

        _promote_suspicious_preconditions(result, self._config(tmp_path))

        promoted = result.outcomes[0]
        assert promoted.status == "finding"
        assert promoted.evidence_tool == (
            "precondition:attacker_controls_input,caller_bounds_checks"
        )
        assert promoted.body.startswith("[precondition-verified via ")
        assert "attacker_controls_input" in promoted.body
        assert "precondition" in (promoted.tools_dispatched or set())
        assert result.precondition_promoted == 1
        assert result.sweep_promoted == 1
        assert result.suspicious == 0
        assert result.findings == 1
        pv = promoted.review_result["precondition_verification"]
        assert pv["all_supported"] is True
        assert len(pv["checks"]) == 2
        tc = result.tier_counters["precondition_promotion"]
        assert tc.confirmed == 1

    def test_promoted_outcome_grades_tool_backed(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _promote_suspicious_preconditions,
        )
        outcome = self._outcome(self._preconditions(
            "function_reaches_sink",
        ))
        result = self._result([outcome])
        self._patch_verdict(monkeypatch, _verdict(
            ("function_reaches_sink", "supported"),
        ))
        _promote_suspicious_preconditions(result, self._config(tmp_path))
        promoted = result.outcomes[0]
        assert promoted.status == "finding"
        assert promoted.compute_tier() == "tool_backed"

    def test_partial_support_stays_suspicious_with_record(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _promote_suspicious_preconditions,
        )
        outcome = self._outcome(self._preconditions(
            "attacker_controls_input", "caller_sanitizes",
        ))
        result = self._result([outcome])
        self._patch_verdict(monkeypatch, _verdict(
            ("attacker_controls_input", "supported"),
            ("caller_sanitizes", "inconclusive"),
        ))

        _promote_suspicious_preconditions(result, self._config(tmp_path))

        kept = result.outcomes[0]
        assert kept.status == "suspicious"
        assert result.precondition_promoted == 0
        pv = kept.review_result["precondition_verification"]
        assert pv["all_supported"] is False
        verdicts = {c["check_type"]: c["verdict"] for c in pv["checks"]}
        assert verdicts["caller_sanitizes"] == "inconclusive"
        tc = result.tier_counters["precondition_promotion"]
        assert tc.inconclusive == 1
        assert tc.confirmed == 0

    def test_contradiction_stays_suspicious_counted_refuted(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _promote_suspicious_preconditions,
        )
        outcome = self._outcome(self._preconditions(
            "attacker_controls_input",
        ))
        result = self._result([outcome])
        self._patch_verdict(monkeypatch, _verdict(
            ("attacker_controls_input", "contradicted"),
        ))

        _promote_suspicious_preconditions(result, self._config(tmp_path))

        assert result.outcomes[0].status == "suspicious"
        tc = result.tier_counters["precondition_promotion"]
        assert tc.refuted == 1
        assert tc.confirmed == 0

    def test_all_supported_without_load_bearing_stays(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _promote_suspicious_preconditions,
        )
        outcome = self._outcome(self._preconditions(
            "caller_bounds_checks", "caller_sanitizes",
        ))
        result = self._result([outcome])
        self._patch_verdict(monkeypatch, _verdict(
            ("caller_bounds_checks", "supported"),
            ("caller_sanitizes", "supported"),
        ))

        _promote_suspicious_preconditions(result, self._config(tmp_path))

        assert result.outcomes[0].status == "suspicious"
        tc = result.tier_counters["precondition_promotion"]
        assert tc.inconclusive == 1

    def test_no_preconditions_untouched(self, tmp_path):
        from core.audit.orchestrator import (
            _promote_suspicious_preconditions,
        )
        outcome = self._outcome([])
        result = self._result([outcome])
        _promote_suspicious_preconditions(result, self._config(tmp_path))
        assert result.outcomes[0].status == "suspicious"
        assert "precondition_verification" not in outcome.review_result

    def test_non_suspicious_skipped(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            _promote_suspicious_preconditions,
        )
        outcome = self._outcome(
            self._preconditions("attacker_controls_input"),
            status="finding",
        )
        result = self._result([outcome])
        called = []
        monkeypatch.setattr(
            "core.audit.precondition_check.verify_preconditions",
            lambda *a, **kw: called.append(1) or _verdict(),
        )
        _promote_suspicious_preconditions(result, self._config(tmp_path))
        assert not called

    def test_gate_demoted_body_skipped(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            _promote_suspicious_preconditions,
        )
        outcome = self._outcome(
            self._preconditions("attacker_controls_input"),
            body="[gate violation: G2] no tool evidence",
        )
        result = self._result([outcome])
        called = []
        monkeypatch.setattr(
            "core.audit.precondition_check.verify_preconditions",
            lambda *a, **kw: called.append(1) or _verdict(),
        )
        _promote_suspicious_preconditions(result, self._config(tmp_path))
        assert not called
        assert result.outcomes[0].status == "suspicious"

    def test_check_count_bounded_per_function(self, tmp_path, monkeypatch):
        from core.audit import orchestrator as orch
        outcome = self._outcome(self._preconditions(
            *["caller_bounds_checks"] * 10,
        ))
        result = self._result([outcome])
        seen = {}

        def fake_verify(preconditions, **kw):
            seen["n"] = len(preconditions)
            return _verdict()

        monkeypatch.setattr(
            "core.audit.precondition_check.verify_preconditions",
            fake_verify,
        )
        orch._promote_suspicious_preconditions(
            result, self._config(tmp_path),
        )
        assert seen["n"] == orch._MAX_PRECONDITION_CHECKS_PER_FN

    def test_audit_log_written_on_promotion(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            _promote_suspicious_preconditions,
        )
        outcome = self._outcome(self._preconditions(
            "attacker_controls_input",
        ))
        result = self._result([outcome])
        self._patch_verdict(monkeypatch, _verdict(
            ("attacker_controls_input", "supported"),
        ))
        config = self._config(tmp_path)

        _promote_suspicious_preconditions(result, config)

        log_path = config.out_dir / ".audit-log.jsonl"
        assert log_path.exists()
        entries = [
            json.loads(line)
            for line in log_path.read_text().splitlines() if line
        ]
        actions = [e.get("action") for e in entries]
        assert "precondition_verified_promotion" in actions
        entry = entries[actions.index("precondition_verified_promotion")]
        assert entry["prior_status"] == "suspicious"
        assert entry["checks"][0]["check_type"] == "attacker_controls_input"


class TestEndToEndCheckers:
    """Exercise the real checkers (no stub) for one supported path."""

    def test_real_checker_supports_expect_absent_bounds(self, tmp_path):
        from core.audit.precondition_check import verify_preconditions
        src = tmp_path / "a.c"
        src.write_text(
            "void f(char *p) {\n"
            "    char buf[8];\n"
            "    memcpy(buf, p, 64);\n"
            "}\n"
        )
        verdict = verify_preconditions(
            [{
                "assumption": "no caller bounds-checks p",
                "check_type": "caller_bounds_checks",
                "location": {"file": "a.c", "function": "f"},
                "expect_absent": True,
                "parameter": "p",
            }],
            target_path=tmp_path,
        )
        assert len(verdict.checks) == 1
        assert verdict.checks[0].verdict == "supported"
        assert verdict.all_supported is True
