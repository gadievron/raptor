"""Tests for ``packages.source_intel.measurement``.

The harness drives N=20-style A/B comparisons that take 25-40 min
of LLM time per run. These tests cover the pure-Python pieces
underneath — verdict mapping, finding→dataflow adapter, corpus
iteration (default + stratified + --verdict filter), the resolver
fallback, and the aggregate-stats math — so refactors don't
silently break the harness between the (rare) live runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel import measurement as M


# =====================================================================
# _verdict_to_label — pure ValidatorVerdict → corpus-label mapping
# =====================================================================

def test_verdict_to_label_exploitable():
    assert M._verdict_to_label(ValidatorVerdict.EXPLOITABLE) == "true_positive"


def test_verdict_to_label_not_exploitable():
    assert M._verdict_to_label(ValidatorVerdict.NOT_EXPLOITABLE) == "false_positive"


def test_verdict_to_label_uncertain():
    # UNCERTAIN must map to the "uncertain" sentinel — corpus ground
    # truth is only TP or FP, so UNCERTAIN never matches and registers
    # as an error against either label (intentional).
    assert M._verdict_to_label(ValidatorVerdict.UNCERTAIN) == "uncertain"


# =====================================================================
# _result_to_verdict — DataflowValidation result → ValidatorVerdict
# =====================================================================

def test_result_to_verdict_true():
    r = SimpleNamespace(is_exploitable=True)
    assert M._result_to_verdict(r) == ValidatorVerdict.EXPLOITABLE


def test_result_to_verdict_false():
    r = SimpleNamespace(is_exploitable=False)
    assert M._result_to_verdict(r) == ValidatorVerdict.NOT_EXPLOITABLE


def test_result_to_verdict_none():
    r = SimpleNamespace(is_exploitable=None)
    assert M._result_to_verdict(r) == ValidatorVerdict.UNCERTAIN


def test_result_to_verdict_missing_attr():
    # `is_exploitable` absent (older mock shape) → UNCERTAIN, not crash.
    r = SimpleNamespace()
    assert M._result_to_verdict(r) == ValidatorVerdict.UNCERTAIN


# =====================================================================
# _is_memory_corruption — rule-id prefix filter
# =====================================================================

def _finding(rule_id: str) -> Finding:
    step = Step(file_path="x.c", line=1, column=1, snippet="x")
    return Finding(
        finding_id="t", producer="codeql", rule_id=rule_id,
        message="m", source=step, sink=step,
    )


def test_is_memory_corruption_matches_known_prefix():
    # cpp/unbounded-write, cpp/null-dereference etc. are in
    # DEFAULT_SOURCE_INTEL_RULE_PREFIXES — check at least one shape.
    assert M._is_memory_corruption(_finding("cpp/unbounded-write"))


def test_is_memory_corruption_rejects_injection_rules():
    # Injection rules belong to the sanitizer collector, not SI.
    assert not M._is_memory_corruption(_finding("py/sql-injection"))


def test_is_memory_corruption_rejects_unrelated():
    assert not M._is_memory_corruption(_finding("js/xss"))


def test_is_memory_corruption_empty_rule_id():
    # Defensive: an empty rule_id should not crash and must return False.
    # Build a finding bypassing post-init validation since Finding
    # rejects empty rule_id strings.
    step = Step(file_path="x.c", line=1, column=1, snippet="x")
    bogus = Finding.__new__(Finding)
    object.__setattr__(bogus, "rule_id", "")
    object.__setattr__(bogus, "source", step)
    object.__setattr__(bogus, "sink", step)
    assert not M._is_memory_corruption(bogus)


# =====================================================================
# _finding_to_dataflow_path — adapter shape
# =====================================================================

def test_finding_to_dataflow_path_basic_shape():
    src = Step(file_path="a.c", line=10, column=3, snippet="src", label="source")
    snk = Step(file_path="a.c", line=20, column=5, snippet="snk", label="sink")
    f = Finding(
        finding_id="t", producer="codeql", rule_id="cpp/unbounded-write",
        message="m", source=src, sink=snk,
    )
    dp = M._finding_to_dataflow_path(f)
    assert dp.source.file_path == "a.c"
    assert dp.source.line == 10
    assert dp.source.column == 3
    assert dp.source.label == "source"
    assert dp.sink.line == 20
    assert dp.sink.label == "sink"
    assert list(dp.intermediate_steps) == []
    assert list(dp.sanitizers) == []
    assert dp.rule_id == "cpp/unbounded-write"
    assert dp.message == "m"


def test_finding_to_dataflow_path_column_zero_normalised_to_one():
    # The adapter coerces column 0 to 1 — DataflowStep requires column >= 1.
    src = Step(file_path="a.c", line=1, column=0, snippet="s")
    snk = Step(file_path="a.c", line=2, column=0, snippet="s")
    f = Finding(
        finding_id="t", producer="codeql", rule_id="cpp/null-dereference",
        message="m", source=src, sink=snk,
    )
    dp = M._finding_to_dataflow_path(f)
    assert dp.source.column == 1
    assert dp.sink.column == 1


def test_finding_to_dataflow_path_intermediate_steps_relabeled():
    src = Step(file_path="a.c", line=1, column=1, snippet="src")
    mid = Step(file_path="a.c", line=10, column=1, snippet="mid", label="ignored")
    snk = Step(file_path="a.c", line=20, column=1, snippet="snk")
    f = Finding(
        finding_id="t", producer="codeql", rule_id="cpp/unbounded-write",
        message="m", source=src, sink=snk,
        intermediate_steps=(mid,),
    )
    dp = M._finding_to_dataflow_path(f)
    assert len(dp.intermediate_steps) == 1
    # Adapter rewrites the label to "step" regardless of input.
    assert dp.intermediate_steps[0].label == "step"


# =====================================================================
# _corpus_scan_target_resolver — sink-parent resolution + fallbacks
# =====================================================================

def test_resolver_returns_sink_parent_when_path_exists(tmp_path: Path):
    f = tmp_path / "sub" / "fixture.c"
    f.parent.mkdir(parents=True)
    f.write_text("")
    dataflow = SimpleNamespace(sink=SimpleNamespace(file_path=str(f)))
    assert M._corpus_scan_target_resolver(dataflow, tmp_path) == f.parent


def test_resolver_falls_back_when_sink_missing(tmp_path: Path):
    dataflow = SimpleNamespace(sink=SimpleNamespace(file_path=""))
    assert M._corpus_scan_target_resolver(dataflow, tmp_path) == tmp_path


def test_resolver_falls_back_when_sink_attr_absent(tmp_path: Path):
    dataflow = SimpleNamespace()  # no .sink at all
    assert M._corpus_scan_target_resolver(dataflow, tmp_path) == tmp_path


def test_resolver_falls_back_when_parent_isnt_dir(tmp_path: Path):
    # Synthesize a sink whose computed parent doesn't actually exist
    # as a directory on disk.
    fake = "/nonexistent_dir_xyz_12345/file.c"
    dataflow = SimpleNamespace(sink=SimpleNamespace(file_path=fake))
    assert M._corpus_scan_target_resolver(dataflow, tmp_path) == tmp_path


# =====================================================================
# _iter_memory_corruption_corpus — the big one. Use tmp corpus dir.
# =====================================================================

def _write_corpus_entry(
    corpus_dir: Path, name: str, *, rule_id: str, verdict: str,
    fp_category=None,
) -> None:
    """Write a finding + label pair into ``corpus_dir``."""
    step = {"file_path": f"{name}.c", "line": 1, "column": 1,
            "snippet": "x", "label": "source"}
    finding = {
        "schema_version": 1,
        "finding_id": name,
        "producer": "codeql",
        "rule_id": rule_id,
        "message": f"{name} message",
        "source": step,
        "sink": {**step, "label": "sink"},
        "intermediate_steps": [],
        "raw": {},
    }
    label = {
        "schema_version": 1,
        "finding_id": name,
        "verdict": verdict,
        "rationale": f"rationale for {name}",
        "labeler": "test",
        "labeled_at": "2026-05-20",
    }
    if verdict == "false_positive" and fp_category:
        label["fp_category"] = fp_category
    (corpus_dir / f"{name}.json").write_text(json.dumps(finding))
    (corpus_dir / f"{name}.label.json").write_text(json.dumps(label))


@pytest.fixture
def fake_corpus(tmp_path, monkeypatch):
    """Stand up a 6-entry corpus the iterator can scan."""
    corpus = tmp_path / "findings"
    corpus.mkdir()
    # Mix of memory-corruption + non-memory-corruption + various verdicts.
    _write_corpus_entry(corpus, "a_tp1",  rule_id="cpp/unbounded-write",   verdict="true_positive")
    _write_corpus_entry(corpus, "b_tp2",  rule_id="cpp/null-dereference",  verdict="true_positive")
    _write_corpus_entry(corpus, "c_fp_fw", rule_id="cpp/unbounded-write",
                        verdict="false_positive", fp_category="framework_mitigation")
    _write_corpus_entry(corpus, "d_fp_ib", rule_id="cpp/null-dereference",
                        verdict="false_positive", fp_category="infeasible_branch")
    _write_corpus_entry(corpus, "e_fp_dc", rule_id="cpp/unbounded-write",
                        verdict="false_positive", fp_category="dead_code")
    # Non-memory-corruption — must be filtered out.
    _write_corpus_entry(corpus, "z_inject", rule_id="py/sql-injection", verdict="true_positive")
    monkeypatch.setattr(M, "_CORPUS_DIR", corpus)
    return corpus


def test_iter_default_returns_top_n_sorted(fake_corpus):
    out = M._iter_memory_corruption_corpus(prefix=None, count=3, stratified=False)
    names = [name for (_, _, name) in out]
    # Sorted-glob order over the 5 memory-corruption entries (z_inject filtered).
    assert names == ["a_tp1.json", "b_tp2.json", "c_fp_fw.json"]


def test_iter_filters_injection_rules(fake_corpus):
    out = M._iter_memory_corruption_corpus(prefix=None, count=100, stratified=False)
    names = {n for (_, _, n) in out}
    assert "z_inject.json" not in names
    assert len(out) == 5  # all memory-corruption entries, no injection


def test_iter_prefix_filter(fake_corpus):
    out = M._iter_memory_corruption_corpus(prefix="a_", count=10, stratified=False)
    assert [n for (_, _, n) in out] == ["a_tp1.json"]


def test_iter_stratified_round_robins_buckets(fake_corpus):
    # 4 buckets exist in fake_corpus:
    #   true_positive (2 entries: a_tp1, b_tp2)
    #   false_positive:framework_mitigation (1: c_fp_fw)
    #   false_positive:infeasible_branch (1: d_fp_ib)
    #   false_positive:dead_code (1: e_fp_dc)
    # With count=4 stratified, we expect one entry from each bucket
    # before any bucket is sampled twice.
    out = M._iter_memory_corruption_corpus(prefix=None, count=4, stratified=True)
    assert len(out) == 4
    verdicts = [
        f"{label.verdict}:{label.fp_category}" if label.verdict == "false_positive"
        else label.verdict
        for (_, label, _) in out
    ]
    # All 4 distinct buckets must be represented exactly once.
    assert set(verdicts) == {
        "true_positive",
        "false_positive:framework_mitigation",
        "false_positive:infeasible_branch",
        "false_positive:dead_code",
    }


def test_iter_stratified_drains_smaller_buckets_first(fake_corpus):
    # count=5 over the same buckets: 1 TP-bucket entry, 1 each from
    # the 3 FP buckets, and then a 2nd round picks the remaining TP.
    out = M._iter_memory_corruption_corpus(prefix=None, count=5, stratified=True)
    assert len(out) == 5
    tp_count = sum(1 for (_, label, _) in out if label.verdict == "true_positive")
    assert tp_count == 2  # both TPs picked
    fp_count = sum(1 for (_, label, _) in out if label.verdict == "false_positive")
    assert fp_count == 3


def test_iter_verdict_true_positive_only(fake_corpus):
    out = M._iter_memory_corruption_corpus(
        prefix=None, count=10, stratified=False, verdict="true_positive",
    )
    verdicts = [label.verdict for (_, label, _) in out]
    assert verdicts == ["true_positive", "true_positive"]


def test_iter_verdict_false_positive_only(fake_corpus):
    out = M._iter_memory_corruption_corpus(
        prefix=None, count=10, stratified=False, verdict="false_positive",
    )
    verdicts = {label.verdict for (_, label, _) in out}
    assert verdicts == {"false_positive"}
    assert len(out) == 3


def test_iter_skips_entries_with_missing_label(fake_corpus):
    # Remove a label file — the finding must be silently skipped.
    (fake_corpus / "a_tp1.label.json").unlink()
    out = M._iter_memory_corruption_corpus(prefix=None, count=10, stratified=False)
    names = {n for (_, _, n) in out}
    assert "a_tp1.json" not in names


def test_iter_skips_entries_with_corrupt_finding_json(fake_corpus):
    # Corrupt one finding file — must be silently skipped, not raise.
    (fake_corpus / "b_tp2.json").write_text("not-valid-json")
    out = M._iter_memory_corruption_corpus(prefix=None, count=10, stratified=False)
    names = {n for (_, _, n) in out}
    assert "b_tp2.json" not in names


# =====================================================================
# _aggregate — pure stats math
# =====================================================================

def _row(*, baseline_correct, si_correct, delta):
    return {"baseline_correct": baseline_correct,
            "si_correct": si_correct, "delta": delta}


def test_aggregate_empty():
    s = M._aggregate([])
    assert s["n"] == 0
    assert s["baseline_errors"] == 0
    assert s["si_errors"] == 0
    assert s["err_reduction"] == 0.0


def test_aggregate_all_improved():
    # Mirrors a TP-heavy "everything got better" hypothetical.
    rows = [
        _row(baseline_correct=False, si_correct=True, delta="improved"),
        _row(baseline_correct=False, si_correct=True, delta="improved"),
    ]
    s = M._aggregate(rows)
    assert s["n"] == 2
    assert s["baseline_errors"] == 2
    assert s["si_errors"] == 0
    assert s["improved"] == 2
    assert s["regressed"] == 0
    assert s["same"] == 0
    assert s["err_reduction"] == 100.0


def test_aggregate_real_run_a_shape():
    # 10/20 baseline errors → 3/20 SI errors, 7 improved 0 regressed
    # 13 same. Exact shape of Run A (gemini-2.5-pro), 2026-05-20.
    rows = []
    rows += [_row(baseline_correct=False, si_correct=True, delta="improved")] * 7
    rows += [_row(baseline_correct=False, si_correct=False, delta="same")] * 3
    rows += [_row(baseline_correct=True,  si_correct=True, delta="same")] * 10
    s = M._aggregate(rows)
    assert s["n"] == 20
    assert s["baseline_errors"] == 10
    assert s["si_errors"] == 3
    assert s["improved"] == 7
    assert s["regressed"] == 0
    assert s["same"] == 13
    # (10 - 3) / 10 * 100 = 70.0
    assert round(s["err_reduction"], 1) == 70.0


def test_aggregate_with_regression():
    # Synthetic case: 1 SI-induced regression. Verify the counter wires
    # through (Run A/B/C all had 0 regressed; this checks the path is
    # ever taken).
    rows = [
        _row(baseline_correct=True,  si_correct=False, delta="regressed"),
        _row(baseline_correct=False, si_correct=True, delta="improved"),
        _row(baseline_correct=True,  si_correct=True, delta="same"),
    ]
    s = M._aggregate(rows)
    assert s["regressed"] == 1
    assert s["improved"] == 1
    assert s["same"] == 1


def test_aggregate_baseline_perfect_si_perfect():
    # All correct, no errors → err_reduction stays 0.0 (the "no
    # headroom" case the Run C TP-only run produced).
    rows = [_row(baseline_correct=True, si_correct=True, delta="same")] * 5
    s = M._aggregate(rows)
    assert s["baseline_errors"] == 0
    assert s["si_errors"] == 0
    assert s["err_reduction"] == 0.0  # 0/0 short-circuit, not NaN
