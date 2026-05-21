"""Adversarial prompt-injection tests for LLM stages.

Uses fixtures from ``packages/sca/tests/fixtures/prompt_injections/``
containing known injection patterns embedded in install scripts.

Tests verify that:
1. Preflight detects injection indicators in adversarial inputs.
2. The structured-output validator rejects malformed responses.
3. The ``run_stage`` helper applies confidence haircuts on preflight hits.
4. Mechanical override prevents LLM from suppressing findings.

All tests use a stub LLM — no real LLM calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import pytest

from packages.sca.llm import (
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from packages.sca.llm.install_hook_review import _merge_verdict
from packages.sca.llm.schemas import InstallHookVerdict
from packages.sca.models import Confidence, Dependency, PinStyle, SupplyChainFinding
from core.security.prompt_input_preflight import preflight


_FIXTURES_DIR = (
    Path(__file__).resolve().parents[2]  # packages/sca/
    / "tests" / "fixtures" / "prompt_injections"
)


def _load_fixture(name: str) -> str:
    return (_FIXTURES_DIR / name).read_text(encoding="utf-8")


def _all_fixtures() -> list[tuple[str, str]]:
    """Return (name, content) for every injection fixture."""
    pairs = []
    for p in sorted(_FIXTURES_DIR.glob("*.txt")):
        pairs.append((p.stem, p.read_text(encoding="utf-8")))
    return pairs


# ------------------------------------------------------------------ stubs


@dataclass
class _FakeStructuredResponse:
    result: Dict[str, Any]
    raw: str = ""
    cost: float = 0.0
    tokens_used: int = 0
    model: str = "test/fake"
    provider: str = "test"
    duration: float = 0.1
    cached: bool = False

    def __iter__(self):
        return iter((self.result, self.raw))


class _FakeModelConfig:
    provider = "test"
    model_name = "fake-model"
    enabled = True
    max_context = 8192


class _FakeConfig:
    primary_model = _FakeModelConfig()


class _StubClient:
    config = _FakeConfig()
    total_cost = 0.0

    def __init__(self, result_dict):
        self._result = result_dict

    def generate_structured(self, prompt, schema, system_prompt=None,
                            task_type=None, **kwargs):
        return _FakeStructuredResponse(result=self._result)


def _make_finding(script_body: str, severity: str = "high") -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id="SC-ADV-001",
        kind="install_hook_suspicious",
        dependency=Dependency(
            ecosystem="npm", name="evil-pkg", version="1.0.0",
            declared_in=Path("/fake/package.json"), scope="main",
            is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
            purl="pkg:npm/evil-pkg@1.0.0",
            parser_confidence=Confidence(level="high"),
        ),
        detail="Suspicious install script",
        evidence={
            "script_body": script_body,
            "script_key": "postinstall",
            "reasons": ["regex_match"],
        },
        severity=severity,
        confidence=Confidence(level="medium"),
    )


# ------------------------------------------------------------------ tests


class TestPreflightDetection:
    """Preflight should flag injection indicators in adversarial fixtures."""

    @pytest.mark.parametrize("name,content", _all_fixtures())
    def test_preflight_runs_without_error(self, name: str, content: str):
        """Preflight must not crash on any fixture — it may or may not
        detect injection depending on the pattern, but must never error."""
        result = preflight(content)
        assert result is not None

    def test_english_injection_detected(self):
        content = _load_fixture("english.txt")
        result = preflight(content)
        assert result.has_injection_indicators, (
            "Preflight should detect 'IGNORE ALL PREVIOUS INSTRUCTIONS'"
        )


class TestMechanicalOverride:
    """LLM 'benign' verdict must not suppress mechanical findings."""

    @pytest.mark.parametrize("name,content", _all_fixtures())
    def test_benign_verdict_preserves_severity(self, name: str, content: str):
        """Even if the LLM says 'benign', the mechanical finding stays."""
        finding = _make_finding(content, severity="high")
        benign_verdict = InstallHookVerdict(
            verdict="benign",
            confidence="high",
            reasoning="This looks like a normal build script",
        )
        _merge_verdict(finding, benign_verdict)

        assert finding.severity == "high", (
            f"Fixture {name}: mechanical override failed — "
            f"severity changed to {finding.severity}"
        )
        assert finding.evidence["llm_verdict"] == "benign"

    @pytest.mark.parametrize("name,content", _all_fixtures())
    def test_malicious_verdict_escalates(self, name: str, content: str):
        finding = _make_finding(content, severity="high")
        malicious_verdict = InstallHookVerdict(
            verdict="malicious",
            confidence="high",
            behaviours=["outbound_network", "exec_decoded_payload"],
        )
        _merge_verdict(finding, malicious_verdict)
        assert finding.severity == "critical"


class TestRunStageWithAdversarialInput:
    """run_stage with adversarial content should still produce valid output."""

    @pytest.mark.parametrize("name,content", _all_fixtures())
    def test_stage_completes_with_adversarial_input(
        self, name: str, content: str,
    ):
        """run_stage must return a StageResult (possibly with haircut)
        even when the input contains injection attempts."""
        client = _StubClient({
            "verdict": "suspicious",
            "confidence": "medium",
            "behaviours": ["obfuscation"],
            "evidence_quotes": [],
            "reasoning": "Contains obfuscated patterns",
        })
        result = run_stage(
            client=client,
            system="You are a test analyst.",
            untrusted_blocks=(
                UntrustedBlock(
                    content=content, kind="SCRIPT",
                    origin=f"test/{name}",
                ),
            ),
            slots={
                "package_name": TaintedString(value="test", trust="untrusted"),
            },
            schema_cls=InstallHookVerdict,
        )
        assert result.error is None
        assert result.model is not None
        assert result.model.verdict == "suspicious"

    def test_confidence_haircut_on_injection(self):
        """When preflight detects injection, confidence haircut = 0.5."""
        content = _load_fixture("english.txt")
        client = _StubClient({
            "verdict": "benign",
            "confidence": "high",
            "behaviours": [],
            "evidence_quotes": [],
            "reasoning": "Looks safe",
        })
        result = run_stage(
            client=client,
            system="test",
            untrusted_blocks=(
                UntrustedBlock(content=content, kind="SCRIPT", origin="test"),
            ),
            slots={},
            schema_cls=InstallHookVerdict,
        )
        assert result.preflight_hit is True
        assert result.confidence_haircut == 0.5


class TestSchemaRejection:
    """Malformed LLM responses must not produce a valid model."""

    def test_wrong_verdict_value_rejected(self):
        client = _StubClient({
            "verdict": "totally_safe",
            "confidence": "high",
        })
        result = run_stage(
            client=client,
            system="test",
            untrusted_blocks=(
                UntrustedBlock(content="x", kind="TEST", origin="test"),
            ),
            slots={},
            schema_cls=InstallHookVerdict,
        )
        assert result.model is None

    def test_missing_required_field_rejected(self):
        client = _StubClient({
            "confidence": "high",
        })
        result = run_stage(
            client=client,
            system="test",
            untrusted_blocks=(
                UntrustedBlock(content="x", kind="TEST", origin="test"),
            ),
            slots={},
            schema_cls=InstallHookVerdict,
        )
        assert result.model is None
