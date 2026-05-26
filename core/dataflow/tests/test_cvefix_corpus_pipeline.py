"""End-to-end smoke test for the CVE-fix trust-corpus pipeline.

Proves the framework plumbing on a SYNTHETIC before/after SARIF pair (no
CodeQL, no dataset download), wiring the shipped substrate to the three new
modules:

  generate_from_sarif  (cvefix_corpus_generator)
    -> write_corpus     (owasp_corpus_generator, reused)
    -> run              (run_corpus, shipped)
    -> report           (trust_report)

The validator here is a STUB suppressor (sanitizer-token match) — it exercises
the framework, not the real trust detector (that's the qlpack sound tier).
"""

from __future__ import annotations

from pathlib import Path

from core.dataflow.cvefix_corpus_generator import generate_from_sarif, write_corpus
from core.dataflow.run_corpus import run
from core.dataflow.trust_report import render, report
from core.dataflow.validator import ValidatorVerdict


def _loc(uri: str, line: int, snippet: str, msg: str) -> dict:
    return {"location": {"physicalLocation": {
        "artifactLocation": {"uri": uri},
        "region": {"startLine": line, "startColumn": 5, "snippet": {"text": snippet}}},
        "message": {"text": msg}}}


def _sarif(sink_line: int, sink_snippet: str) -> dict:
    return {"runs": [{"results": [{
        "ruleId": "java/sql-injection",
        "message": {"text": "user input reaches SQL"},
        "codeFlows": [{"threadFlows": [{"locations": [
            _loc("Foo.java", 10, 'request.getParameter("id")', "source"),
            _loc("Foo.java", sink_line, sink_snippet, "sink"),
        ]}]}]}]}]}


# Vulnerable (pre-fix) vs patched (post-fix, sanitizer added but CodeQL still flags).
_BEFORE = _sarif(20, "stmt.execute(sql)")
_AFTER = _sarif(22, "stmt.execute(Sanitizer.clean(sql))")


class _SanitizerTokenValidator:
    """Stub trust suppressor: NOT_EXPLOITABLE if a sanitizer token is on the
    path, else UNCERTAIN (never EXPLOITABLE). Plumbing stand-in only."""

    def validate(self, finding) -> ValidatorVerdict:
        path = [finding.source, *finding.intermediate_steps, finding.sink]
        blob = " ".join((s.snippet or "") for s in path).lower()
        if any(t in blob for t in ("sanitizer", "clean(", "escape(")):
            return ValidatorVerdict.NOT_EXPLOITABLE
        return ValidatorVerdict.UNCERTAIN


class _SuppressAllValidator:
    """Unsound suppressor — suppresses everything. Used to prove the FN-gate
    actually fires (it must mark a TP false-suppression)."""

    def validate(self, finding) -> ValidatorVerdict:
        return ValidatorVerdict.NOT_EXPLOITABLE


def _generate(**kw):
    return generate_from_sarif(
        _BEFORE, _AFTER, cve_id="CVE-2021-9999", cwe="CWE-89",
        labeled_at="2026-05-25", **kw,
    )


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def test_generator_labels_post_fix_finding_as_missing_sanitizer_fp():
    pairs = _generate()
    by_verdict = {gt.verdict: (f, gt) for f, gt in pairs}
    assert set(by_verdict) == {"true_positive", "false_positive"}
    f_fp, gt_fp = by_verdict["false_positive"]
    assert gt_fp.fp_category == "missing_sanitizer_model"
    assert "post" in f_fp.finding_id
    assert "Sanitizer.clean" in f_fp.sink.snippet
    f_tp, gt_tp = by_verdict["true_positive"]
    assert gt_tp.fp_category is None
    assert "pre" in f_tp.finding_id


def test_generator_skips_non_dataflow_results():
    empty = {"runs": [{"results": [{"ruleId": "x", "message": {"text": "no flow"}}]}]}
    pairs = generate_from_sarif(empty, empty, cve_id="CVE-X", cwe="CWE-89",
                                labeled_at="2026-05-25")
    assert pairs == []


# ---------------------------------------------------------------------------
# End-to-end: generate -> write_corpus -> run_corpus -> trust_report
# ---------------------------------------------------------------------------

def test_pipeline_suppresses_fp_without_false_suppressing_tp(tmp_path: Path):
    corpus_dir = tmp_path / "corpus"
    n = write_corpus(_generate(), corpus_dir)
    assert n == 2

    csv_out = tmp_path / "trust.csv"
    rows = run(corpus_dir, _SanitizerTokenValidator(), csv_out)
    assert rows == 2

    r = report(csv_out)
    assert r.trust_fp == 1
    assert r.coverage_n == 1          # the post-fix FP was suppressed
    assert r.coverage == 1.0
    assert r.tp == 1
    assert r.false_suppression_n == 0  # the pre-fix TP was NOT suppressed
    assert r.is_sound
    assert "coverage:" in render(r)


def test_fn_gate_fires_when_a_tp_is_suppressed(tmp_path: Path):
    """An unsound validator that suppresses the TP must register as a
    false-suppression and flip is_sound — otherwise the gate is decorative."""
    corpus_dir = tmp_path / "corpus"
    write_corpus(_generate(), corpus_dir)
    csv_out = tmp_path / "trust.csv"
    run(corpus_dir, _SuppressAllValidator(), csv_out)
    r = report(csv_out)
    assert r.false_suppression_n == 1
    assert not r.is_sound


# ---------------------------------------------------------------------------
# Localization (Issue 1 fix) + robustness
# ---------------------------------------------------------------------------

def _result(uri: str, sink_line: int) -> dict:
    return {"ruleId": "java/sql-injection", "message": {"text": "m"},
            "codeFlows": [{"threadFlows": [{"locations": [
                _loc(uri, 5, "src", "source"), _loc(uri, sink_line, "sink", "sink")]}]}]}


def test_localization_filters_cve_unrelated_findings():
    # Two findings: one in the fix-changed file, one unrelated.
    after = {"runs": [{"results": [_result("Foo.java", 22), _result("Other.java", 99)]}]}
    empty = {"runs": [{"results": []}]}

    # No localization → both emitted (and the unrelated one is mislabeled FP).
    assert len(generate_from_sarif(after, empty, cve_id="CVE-A", cwe="CWE-89",
                                   labeled_at="2026-05-25")) == 2
    # Localized to Foo.java → only the CVE-attributable finding survives.
    pairs = generate_from_sarif(after, empty, cve_id="CVE-A", cwe="CWE-89",
                                labeled_at="2026-05-25", fix_touched_files={"Foo.java"})
    assert len(pairs) == 1
    assert pairs[0][0].sink.file_path == "Foo.java"


def test_malformed_sarif_result_is_skipped_not_fatal():
    # startLine 0 makes Step validation raise inside from_sarif_result;
    # the generator must skip it, not crash the batch.
    bad = {"runs": [{"results": [{
        "ruleId": "x", "message": {"text": "m"},
        "codeFlows": [{"threadFlows": [{"locations": [
            _loc("F.java", 0, "src", "source"), _loc("F.java", 5, "sink", "sink")]}]}]}]}]}
    empty = {"runs": [{"results": []}]}
    assert generate_from_sarif(bad, empty, cve_id="CVE-B", cwe="CWE-89",
                               labeled_at="2026-05-25") == []
