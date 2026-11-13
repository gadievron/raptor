"""OWASP snippets follow CodeQL source line coordinates."""

from core.dataflow.finding import Finding, Step
from core.dataflow.owasp_corpus_generator import _rewrite_finding_paths_and_snippets


def test_backfill_uses_lf_source_coordinates(tmp_path):
    source = tmp_path / "fixture/src/Foo.java"
    source.parent.mkdir(parents=True)
    source.write_bytes("first\rinline\u2028still_first\nsecond\r\nthird\n".encode("utf-8"))
    finding = Finding(
        finding_id="fixture", producer="codeql", rule_id="java/x", message="m",
        source=Step(file_path="src/Foo.java", line=2, column=0, snippet="", label="source"),
        sink=Step(file_path="src/Foo.java", line=3, column=0, snippet="", label="sink"),
    )
    rewritten = _rewrite_finding_paths_and_snippets(finding, "fixture", repo_root=tmp_path)
    assert rewritten.source.snippet == "second"
    assert rewritten.sink.snippet == "third"
