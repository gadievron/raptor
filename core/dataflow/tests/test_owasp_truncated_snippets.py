"""Capped source prefixes cannot stand in for complete snippet lines."""

from core.dataflow.finding import Finding, Step
from core.dataflow import owasp_corpus_generator as generator
from core.source import read_text_capped


def test_backfill_omits_partial_single_line_but_retains_complete_prefix(tmp_path, monkeypatch):
    source = tmp_path / "fixture/src/Foo.java"
    source.parent.mkdir(parents=True)
    finding = Finding(
        finding_id="fixture", producer="codeql", rule_id="java/x", message="m",
        source=Step(file_path="src/Foo.java", line=1, column=0, snippet="", label="source"),
        sink=Step(file_path="src/Foo.java", line=2, column=0, snippet="", label="sink"),
    )
    monkeypatch.setattr(generator, "read_text_capped", lambda path, **kwargs: read_text_capped(path, 8, **kwargs))
    source.write_text("unbroken source beyond cap", encoding="utf-8")
    result = generator._rewrite_finding_paths_and_snippets(finding, "fixture", repo_root=tmp_path)
    assert result.source.snippet == ""
    assert result.sink.snippet == ""
    source.write_text("first\nsecond line exceeds cap", encoding="utf-8")
    result = generator._rewrite_finding_paths_and_snippets(finding, "fixture", repo_root=tmp_path)
    assert result.source.snippet == "first"
    assert result.sink.snippet == ""
    source.write_text("complete", encoding="utf-8")
    result = generator._rewrite_finding_paths_and_snippets(finding, "fixture", repo_root=tmp_path)
    assert result.source.snippet == "complete"
