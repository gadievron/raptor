"""Tests for ``core.dataflow.owasp_corpus_generator``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.dataflow import (
    FP_MISSING_SANITIZER_MODEL,
    Finding,
    GroundTruth,
    Step,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)
from core.dataflow.owasp_corpus_generator import (
    _balance_subsample,
    _rewrite_finding_paths_and_snippets,
    _test_name_for_finding,
    generate,
    parse_expected_results,
    write_corpus,
)


def _step(file_path: str, line: int = 1, label: str = "step") -> Step:
    return Step(file_path=file_path, line=line, column=0, snippet="x", label=label)


def _finding(source_path: str, sink_path: str = "x.java", finding_id: str = "f1") -> Finding:
    return Finding(
        finding_id=finding_id,
        producer="codeql",
        rule_id="java/command-line-injection",
        message="m",
        source=_step(source_path, label="source"),
        sink=_step(sink_path, label="sink"),
    )


# -------------------------------------------------------------------
# parse_expected_results
# -------------------------------------------------------------------


def test_parse_expected_results_loads_csv(tmp_path: Path):
    csv = tmp_path / "expected.csv"
    csv.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,pathtraver,false,22\n"
        "BenchmarkTest00006,cmdi,true,78\n"
    )
    m = parse_expected_results(csv)
    assert m == {
        "BenchmarkTest00001": (22, True),
        "BenchmarkTest00002": (22, False),
        "BenchmarkTest00006": (78, True),
    }


def test_parse_expected_results_skips_comment_and_malformed_rows(tmp_path: Path):
    csv = tmp_path / "expected.csv"
    csv.write_text(
        "# OWASP-style header comment\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "comment row only,\n"
        "NotABenchmarkTest,x,true,22\n"
    )
    m = parse_expected_results(csv)
    assert m == {"BenchmarkTest00001": (22, True)}


# -------------------------------------------------------------------
# _test_name_for_finding
# -------------------------------------------------------------------


def test_test_name_extracted_from_source_path():
    f = _finding(
        "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00006.java"
    )
    assert _test_name_for_finding(f) == "BenchmarkTest00006"


def test_test_name_extracted_from_sink_when_source_missing():
    f = _finding(
        source_path="x.java",
        sink_path="src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00042.java",
    )
    assert _test_name_for_finding(f) == "BenchmarkTest00042"


def test_test_name_returns_none_when_unrelated_paths():
    f = _finding("a/b/c.java", "d/e/f.java")
    assert _test_name_for_finding(f) is None


# -------------------------------------------------------------------
# _rewrite_finding_paths
# -------------------------------------------------------------------


def test_rewrite_finding_paths_prepends_prefix(tmp_path: Path):
    f = _finding("src/main/java/Foo.java", "src/main/java/Bar.java")
    rewritten = _rewrite_finding_paths_and_snippets(
        f,
        "out/dataflow-corpus-fixtures/owasp-benchmark-java",
        repo_root=tmp_path,
    )
    assert rewritten.source.file_path == (
        "out/dataflow-corpus-fixtures/owasp-benchmark-java/src/main/java/Foo.java"
    )
    assert rewritten.sink.file_path == (
        "out/dataflow-corpus-fixtures/owasp-benchmark-java/src/main/java/Bar.java"
    )


def test_rewrite_finding_paths_idempotent_when_already_prefixed(tmp_path: Path):
    prefix = "out/dataflow-corpus-fixtures/owasp-benchmark-java"
    f = _finding(f"{prefix}/src/main/java/Foo.java", f"{prefix}/src/main/java/Bar.java")
    rewritten = _rewrite_finding_paths_and_snippets(f, prefix, repo_root=tmp_path)
    assert rewritten.source.file_path == f.source.file_path


def test_rewrite_finding_backfills_empty_snippet_from_source(tmp_path: Path):
    src = tmp_path / "out/dataflow-corpus-fixtures/owasp-benchmark-java/src/Foo.java"
    src.parent.mkdir(parents=True)
    src.write_text("line1\nline2_actual_content\nline3\n")
    bare = Step(file_path="src/Foo.java", line=2, column=0, snippet="", label="source")
    bare_sink = Step(file_path="src/Foo.java", line=3, column=0, snippet="", label="sink")
    f = Finding(
        finding_id="f1",
        producer="codeql",
        rule_id="java/x",
        message="m",
        source=bare,
        sink=bare_sink,
    )
    rewritten = _rewrite_finding_paths_and_snippets(
        f,
        "out/dataflow-corpus-fixtures/owasp-benchmark-java",
        repo_root=tmp_path,
    )
    assert rewritten.source.snippet == "line2_actual_content"
    assert rewritten.sink.snippet == "line3"


def test_rewrite_finding_preserves_existing_snippet(tmp_path: Path):
    src = tmp_path / "out/dataflow-corpus-fixtures/owasp-benchmark-java/src/Foo.java"
    src.parent.mkdir(parents=True)
    src.write_text("ignored\n")
    s = Step(file_path="src/Foo.java", line=1, column=0, snippet="explicit", label="source")
    sink = Step(file_path="src/Foo.java", line=1, column=0, snippet="explicit_sink", label="sink")
    f = Finding(
        finding_id="f1",
        producer="codeql",
        rule_id="java/x",
        message="m",
        source=s,
        sink=sink,
    )
    rewritten = _rewrite_finding_paths_and_snippets(
        f,
        "out/dataflow-corpus-fixtures/owasp-benchmark-java",
        repo_root=tmp_path,
    )
    assert rewritten.source.snippet == "explicit"
    assert rewritten.sink.snippet == "explicit_sink"


# -------------------------------------------------------------------
# _balance_subsample
# -------------------------------------------------------------------


def _label(verdict: str, fid: str, fp_category: str | None = None) -> GroundTruth:
    return GroundTruth(
        finding_id=fid,
        verdict=verdict,
        rationale="r",
        labeler="t",
        labeled_at="2026-05-10",
        fp_category=fp_category,
    )


def _pairs(n_tp: int, n_fp: int) -> list:
    out = []
    for i in range(n_tp):
        fid = f"tp_{i:03d}"
        out.append((_finding("a.java", finding_id=fid), _label(VERDICT_TRUE_POSITIVE, fid)))
    for i in range(n_fp):
        fid = f"fp_{i:03d}"
        out.append((
            _finding("a.java", finding_id=fid),
            _label(VERDICT_FALSE_POSITIVE, fid, fp_category=FP_MISSING_SANITIZER_MODEL),
        ))
    return out


def test_balance_subsample_picks_50_50_when_possible():
    pairs = _pairs(50, 50)
    chosen = _balance_subsample(pairs, target=10, seed=0)
    tps = sum(1 for _, l in chosen if l.verdict == VERDICT_TRUE_POSITIVE)
    fps = sum(1 for _, l in chosen if l.verdict == VERDICT_FALSE_POSITIVE)
    assert tps == 5 and fps == 5


def test_balance_subsample_returns_all_when_under_target():
    pairs = _pairs(3, 2)
    chosen = _balance_subsample(pairs, target=10, seed=0)
    assert len(chosen) == 5


def test_balance_subsample_handles_skewed_pool():
    pairs = _pairs(50, 2)
    chosen = _balance_subsample(pairs, target=10, seed=0)
    fps = [p for p in chosen if p[1].verdict == VERDICT_FALSE_POSITIVE]
    tps = [p for p in chosen if p[1].verdict == VERDICT_TRUE_POSITIVE]
    assert len(fps) == 2
    assert len(tps) == 8


def test_balance_subsample_deterministic_with_seed():
    pairs = _pairs(20, 20)
    a = _balance_subsample(pairs, target=10, seed=42)
    b = _balance_subsample(pairs, target=10, seed=42)
    assert [f.finding_id for f, _ in a] == [f.finding_id for f, _ in b]


# -------------------------------------------------------------------
# generate
# -------------------------------------------------------------------


def _sarif_with(test_name: str, source_line: int = 19, sink_line: int = 25) -> dict:
    src_path = f"src/main/java/org/owasp/benchmark/testcode/{test_name}.java"
    return {
        "runs": [{
            "results": [{
                "ruleId": "java/command-line-injection",
                "message": {"text": "test message"},
                "codeFlows": [{
                    "threadFlows": [{
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": src_path},
                                        "region": {
                                            "startLine": source_line,
                                            "startColumn": 1,
                                            "snippet": {"text": "String s = req.getParameter(\"x\")"}
                                        }
                                    },
                                    "message": {"text": "source"}
                                }
                            },
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": src_path},
                                        "region": {
                                            "startLine": sink_line,
                                            "startColumn": 1,
                                            "snippet": {"text": "Runtime.getRuntime().exec(s)"}
                                        }
                                    },
                                    "message": {"text": "sink"}
                                }
                            },
                        ]
                    }]
                }]
            }]
        }]
    }


def test_generate_labels_tp_correctly(tmp_path: Path):
    sarif = tmp_path / "result.sarif"
    sarif.write_text(json.dumps(_sarif_with("BenchmarkTest00006")))
    csv = tmp_path / "expected.csv"
    csv.write_text("# header\nBenchmarkTest00006,cmdi,true,78\n")

    pairs = generate(
        sarif_path=sarif,
        expected_results_csv=csv,
        repo_relative_prefix="out/dataflow-corpus-fixtures/owasp-benchmark-java",
        repo_root=tmp_path,
        target_count=10,
        cwe_filter=78,
    )
    assert len(pairs) == 1
    finding, label = pairs[0]
    assert label.verdict == VERDICT_TRUE_POSITIVE
    assert label.fp_category is None
    assert "BenchmarkTest00006" in finding.finding_id
    assert finding.source.file_path.startswith(
        "out/dataflow-corpus-fixtures/owasp-benchmark-java/"
    )


def test_generate_labels_fp_correctly_with_missing_sanitizer_model(tmp_path: Path):
    sarif = tmp_path / "result.sarif"
    sarif.write_text(json.dumps(_sarif_with("BenchmarkTest00051")))
    csv = tmp_path / "expected.csv"
    csv.write_text("# header\nBenchmarkTest00051,cmdi,false,78\n")

    pairs = generate(
        sarif_path=sarif,
        expected_results_csv=csv,
        repo_relative_prefix="out/dataflow-corpus-fixtures/owasp-benchmark-java",
        repo_root=tmp_path,
        target_count=10,
    )
    assert len(pairs) == 1
    _, label = pairs[0]
    assert label.verdict == VERDICT_FALSE_POSITIVE
    assert label.fp_category == FP_MISSING_SANITIZER_MODEL


def test_generate_filters_by_cwe(tmp_path: Path):
    sarif_obj = _sarif_with("BenchmarkTest00001")
    sarif_obj["runs"][0]["results"].append(
        _sarif_with("BenchmarkTest00006")["runs"][0]["results"][0]
    )
    sarif = tmp_path / "result.sarif"
    sarif.write_text(json.dumps(sarif_obj))
    csv = tmp_path / "expected.csv"
    csv.write_text(
        "# header\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00006,cmdi,true,78\n"
    )

    pairs = generate(
        sarif_path=sarif,
        expected_results_csv=csv,
        repo_relative_prefix="out/dataflow-corpus-fixtures/owasp-benchmark-java",
        repo_root=tmp_path,
        target_count=10,
        cwe_filter=78,
    )
    assert len(pairs) == 1
    assert "BenchmarkTest00006" in pairs[0][0].finding_id


def test_generate_skips_findings_without_test_name(tmp_path: Path):
    sarif_obj = _sarif_with("BenchmarkTest00006")
    # Add a finding pointing at a non-benchmark path
    sarif_obj["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][0][
        "location"
    ]["physicalLocation"]["artifactLocation"]["uri"] = "src/main/java/UnrelatedTest.java"
    sarif_obj["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][1][
        "location"
    ]["physicalLocation"]["artifactLocation"]["uri"] = "src/main/java/UnrelatedTest.java"
    sarif = tmp_path / "result.sarif"
    sarif.write_text(json.dumps(sarif_obj))
    csv = tmp_path / "expected.csv"
    csv.write_text("# header\nBenchmarkTest00006,cmdi,true,78\n")

    pairs = generate(
        sarif_path=sarif,
        expected_results_csv=csv,
        repo_relative_prefix="out/dataflow-corpus-fixtures/owasp-benchmark-java",
        repo_root=tmp_path,
        target_count=10,
    )
    assert pairs == []


def test_write_corpus_emits_paired_files(tmp_path: Path):
    finding = _finding("a.java", finding_id="owasp_test_demo")
    label = _label(VERDICT_TRUE_POSITIVE, "owasp_test_demo")
    out = tmp_path / "findings"
    n = write_corpus([(finding, label)], out)
    assert n == 1
    assert (out / "owasp_test_demo.json").exists()
    assert (out / "owasp_test_demo.label.json").exists()
