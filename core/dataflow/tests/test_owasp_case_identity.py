"""Benchmark labels attach to canonical case filenames only."""

from core.dataflow.finding import Finding, Step
from core.dataflow.owasp_corpus_generator import _test_name_for_finding


def test_case_identity_requires_exact_ascii_java_filename():
    def finding(path, sink="other.java"):
        return Finding(
            finding_id="fixture", producer="codeql", rule_id="java/x", message="m",
            source=Step(file_path=path, line=1, column=0, snippet="", label="source"),
            sink=Step(file_path=sink, line=1, column=0, snippet="", label="sink"),
        )
    for path in (
        "src/BenchmarkTest00001/helper.java", "src/BenchmarkTest000010.java",
        "src/MyBenchmarkTest00001.java", "src/BenchmarkTest00001.java.bak",
        "src/BenchmarkTest００００１.java",
    ):
        assert _test_name_for_finding(finding(path)) is None
        assert _test_name_for_finding(finding(path, "src/BenchmarkTest00042.java")) == "BenchmarkTest00042"
    for path in ("BenchmarkTest00001.java", "src/testcode/BenchmarkTest00001.java"):
        assert _test_name_for_finding(finding(path)) == "BenchmarkTest00001"
