"""Unit tests for the efficacy harness — no live LLM.

The LLM call is injected, so a fake Completer lets us test the A/B logic,
prompt isolation, grading, and corpus loading deterministically.
"""

from __future__ import annotations

import textwrap

from packages.strategy_eval.efficacy import (
    build_prompts,
    format_report,
    grade,
    load_corpus,
    run_ab,
    run_efficacy_eval,
)
from packages.strategy_eval.models import EfficacySample


def _sample(variant: str = "vulnerable") -> EfficacySample:
    return EfficacySample(
        id=f"ld_{variant}",
        strategy="lifecycle_drift",
        code="int may_access(struct task *t){ return get_dumpable(t->mm); }",
        variant=variant,
        synthetic=True,
    )


# --- grading ---------------------------------------------------------------


def test_grade_parses_verdict():
    assert grade("reasoning...\nVERDICT: VULNERABLE")
    assert grade("VERDICT: vulnerable")  # case-insensitive
    assert not grade("looks fine\nVERDICT: SAFE")
    assert not grade("")


# --- prompt isolation ------------------------------------------------------


def test_build_prompts_isolates_the_lens():
    control, treatment, user = build_prompts(_sample())
    # The target lens's exemplar appears ONLY in treatment.
    assert "CVE-2026-46333" not in control
    assert "CVE-2026-46333" in treatment
    # Both carry the always-on baseline + the review contract.
    assert "## Strategy: general" in control
    assert "## Strategy: general" in treatment
    assert "VERDICT:" in control and "VERDICT:" in treatment
    # User prompt is the code under review.
    assert "get_dumpable" in user


# --- A/B lift --------------------------------------------------------------


def _lens_helps(system_prompt: str, user_prompt: str) -> str:
    """Fake model: flags the bug only when the lifecycle_drift lens is
    present (i.e. only under treatment). Simulates a genuinely-helpful
    lens so we can assert the harness measures the lift."""
    return (
        "VERDICT: VULNERABLE"
        if "CVE-2026-46333" in system_prompt
        else "VERDICT: SAFE"
    )


def test_run_ab_measures_lift_on_vulnerable_sample():
    r = run_ab(_sample("vulnerable"), _lens_helps, runs=4)
    assert r.runs == 4
    assert r.control_flagged == 0      # baseline misses it
    assert r.treatment_flagged == 4    # the lens catches it every run


def test_run_ab_no_false_positive_when_model_says_safe():
    always_safe = lambda s, u: "VERDICT: SAFE"  # noqa: E731
    r = run_ab(_sample("patched"), always_safe, runs=3)
    assert r.control_flagged == 0 and r.treatment_flagged == 0


def test_format_report_renders_lift_and_fp_lines():
    results = run_efficacy_eval(
        [_sample("vulnerable"), _sample("patched")], _lens_helps, runs=2,
    )
    report = format_report(results)
    assert "lifecycle_drift:" in report
    assert "vulnerable" in report and "lift" in report
    assert "patched" in report and "false-pos" in report


# --- corpus loading --------------------------------------------------------


def test_load_corpus_reads_manifest_and_code(tmp_path):
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "vuln.c").write_text("int f(){return get_dumpable(0);}")
    (tmp_path / "manifest.yml").write_text(textwrap.dedent("""
        samples:
          - id: ld_vuln
            strategy: lifecycle_drift
            file: samples/vuln.c
            variant: vulnerable
            synthetic: true
    """))
    samples = load_corpus(tmp_path)
    assert len(samples) == 1
    s = samples[0]
    assert s.id == "ld_vuln" and s.strategy == "lifecycle_drift"
    assert s.variant == "vulnerable" and s.synthetic is True
    assert "get_dumpable" in s.code
