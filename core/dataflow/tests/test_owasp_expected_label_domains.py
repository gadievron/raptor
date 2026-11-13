"""Benchmark truth flags cannot silently become false-positive labels."""

import pytest

from core.dataflow.owasp_corpus_generator import parse_expected_results


def test_expected_labels_require_boolean_flags_and_consistent_duplicates(tmp_path):
    path = tmp_path / "expected.csv"

    def write(rows):
        path.write_text("# fixture header\n" + "\n".join(rows) + "\n", encoding="utf-8")

    for flag in ("", "unknown", "0", "1", "maybe"):
        write([f"BenchmarkTest00001,pathtraver,{flag},22"])
        with pytest.raises(ValueError, match="truth flag"):
            parse_expected_results(path)
    write(["BenchmarkTest00001,pathtraver, TRUE ,22",
           "BenchmarkTest00002,pathtraver,FALSE,22",
           "BenchmarkTest00001,pathtraver,true,22"])
    assert parse_expected_results(path) == {
        "BenchmarkTest00001": (22, True), "BenchmarkTest00002": (22, False),
    }
    for conflicting in ("BenchmarkTest00001,pathtraver,false,22",
                        "BenchmarkTest00001,cmdi,true,78"):
        write(["BenchmarkTest00001,pathtraver,true,22", conflicting])
        with pytest.raises(ValueError, match="conflicting"):
            parse_expected_results(path)
    write(["comment row only,", "NotABenchmarkTest,x,unknown,22",
           "BenchmarkTest00003,x,unknown,not-a-cwe", "BenchmarkTest00001,pathtraver,true,22"])
    assert parse_expected_results(path) == {"BenchmarkTest00001": (22, True)}
