"""Un-mocked engine-truth tests for the synthesis mechanical controls.

The stub-engine tests in test_synthesise.py exercise the fail-closed
branches with fabricated error strings; pre-U14-F3 the real semgrep
adapter could never produce those strings (the runner hardcoded
errors=[]), so the branches were dead code in production. These tests
run the REAL engines (skip-gated on availability) and assert that an
invalid rule surfaces as an engine error — never as verified silence
that lets a control pass vacuously.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.checker_synthesis.models import SeedBug, SynthesisedRule
from packages.checker_synthesis.synthesise import (
    _dual_control,
    _run_coccinelle,
    _run_semgrep,
    synthesise_and_run,
)

HAVE_SEMGREP = shutil.which("semgrep") is not None
HAVE_SPATCH = shutil.which("spatch") is not None

needs_semgrep = pytest.mark.skipif(
    not HAVE_SEMGREP, reason="semgrep not installed",
)
needs_spatch = pytest.mark.skipif(
    not HAVE_SPATCH, reason="coccinelle not installed",
)

_INVALID_SEMGREP_RULE = (
    "rules:\n"
    "  - id: deliberately.invalid\n"
    "    message: x\n"
    "    languages: [python]\n"
    "    severity: ERROR\n"
    "    patterns-oops: [x]\n"
)

_VALID_SEMGREP_RULE = (
    "rules:\n"
    "  - id: probe.exec\n"
    "    message: exec call\n"
    "    languages: [python]\n"
    "    severity: ERROR\n"
    "    pattern: exec(...)\n"
)


def _probe_or_skip_semgrep(tmp_path: Path) -> None:
    """Skip when the sandboxed adapter path cannot run semgrep at all
    (e.g. core.sandbox unavailable on this host) — these tests verify
    error semantics of runs that executed, not sandbox availability."""
    rule = tmp_path / "probe.yaml"
    rule.write_text(_VALID_SEMGREP_RULE, encoding="utf-8")
    target = tmp_path / "probe.py"
    target.write_text("exec('x')\n", encoding="utf-8")
    matches, errors = _run_semgrep(rule, target)
    if errors or not matches:
        pytest.skip(f"semgrep adapter probe failed on this host: {errors}")


@needs_semgrep
class TestSemgrepAdapterTruth:
    def test_invalid_rule_surfaces_engine_error(self, tmp_path):
        _probe_or_skip_semgrep(tmp_path)
        rule = tmp_path / "bad.yaml"
        rule.write_text(_INVALID_SEMGREP_RULE, encoding="utf-8")
        target = tmp_path / "t.py"
        target.write_text("x = 1\n", encoding="utf-8")
        matches, errors = _run_semgrep(rule, target)
        assert matches == []
        assert errors, "invalid rule read as verified silence"

    def test_dual_control_fails_closed_on_invalid_rule(self, tmp_path):
        _probe_or_skip_semgrep(tmp_path)
        rule_path = tmp_path / "bad.yaml"
        rule_path.write_text(_INVALID_SEMGREP_RULE, encoding="utf-8")
        rule = SynthesisedRule(
            engine="semgrep", rule_id="bad", body=_INVALID_SEMGREP_RULE,
            test_positive="exec('x')\n", test_negative="y = 2\n",
        )
        ok, errors = _dual_control(rule, rule_path, "semgrep", ".py")
        assert ok is False
        assert errors, "invalid rule passed dual control vacuously"


@needs_spatch
class TestCoccinelleAdapterTruth:
    def test_invalid_rule_surfaces_engine_error(self, tmp_path):
        rule = tmp_path / "bad.cocci"
        rule.write_text("@r@\nthis is not smpl\n", encoding="utf-8")
        target = tmp_path / "t.c"
        target.write_text("void f(void) { g(1); }\n", encoding="utf-8")
        matches, errors = _run_coccinelle(rule, target)
        assert matches == []
        assert errors, "invalid SmPL rule read as verified silence"


@needs_semgrep
class TestSynthesisEndToEndTruth:
    def test_llm_invalid_rule_never_reaches_library(self, tmp_path):
        """End-to-end: an LLM that emits a schema-invalid rule body must
        produce engine errors on the control runs and no library-tier
        rule — never a vacuous pass through the mechanical chain."""
        _probe_or_skip_semgrep(tmp_path)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            "def handler(cmd):\n    exec(cmd)\n", encoding="utf-8",
        )
        seed = SeedBug(
            file="app.py", function="handler",
            line_start=2, line_end=2,
            cwe="CWE-95", reasoning="exec of untrusted input",
        )

        def llm(prompt, schema, system_prompt):
            return {
                "rule_body": _INVALID_SEMGREP_RULE,
                "rationale": "r",
                "test_positive": "exec('x')\n",
                "test_negative": "y = 2\n",
                "fix_patch": "    pass\n",
            }

        result = synthesise_and_run(
            seed, repo, tmp_path / "out", llm, max_retries=1,
        )
        assert result.rule_tier != "library"
        assert result.dual_control is not True
        assert result.errors
        # The engine's real complaint surfaced — not silence.
        assert any(
            "InvalidRuleSchemaError" in e or "returncode" in e
            or "did not match seed" in e
            for e in result.errors
        )
