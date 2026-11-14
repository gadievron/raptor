"""Inert typed location controls; no source analysis or native discovery."""

from core.dataflow.finding import Finding, Step
from packages.source_intel.adapter import _double_free_supports_finding
from packages.source_intel.analyze import DoubleFreeEvidence, SourceIntelResult


def _finding(source, sink):
    return Finding(
        finding_id="owned", producer="codeql", rule_id="cpp/double-free", message="owned",
        source=Step(file_path=source, line=7, column=1, snippet="", label="source"),
        sink=Step(file_path=sink, line=100, column=1, snippet="", label="sink"),
        intermediate_steps=(), raw={},
    )


def _result(path, line):
    return SourceIntelResult(double_frees=(DoubleFreeEvidence(
        role="second", free_fn="kfree", location=(path, line),
    ),))


def test_source_line_cannot_support_different_sink_file(tmp_path):
    source, sink = str(tmp_path / "source.c"), str(tmp_path / "sink.c")
    assert not _double_free_supports_finding(
        _finding(source, sink), _result(sink, 7), repo_root=tmp_path,
    )


def test_source_endpoint_uses_its_own_file(tmp_path):
    source, sink = str(tmp_path / "source.c"), str(tmp_path / "sink.c")
    assert _double_free_supports_finding(
        _finding(source, sink), _result(source, 9), repo_root=tmp_path,
    )


def test_relative_sink_endpoint_retains_tolerance(tmp_path):
    assert _double_free_supports_finding(
        _finding("source.c", "sink.c"), _result(str(tmp_path / "sink.c"), 103),
        repo_root=tmp_path,
    )


def test_unresolvable_source_does_not_hide_sink_evidence(tmp_path, monkeypatch):
    from pathlib import Path

    original = Path.resolve

    def resolve(path, *args, **kwargs):
        if path.name == "source.c":
            raise RuntimeError("owned source resolution refusal")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    assert _double_free_supports_finding(
        _finding("source.c", str(tmp_path / "sink.c")),
        _result(str(tmp_path / "sink.c"), 100), repo_root=tmp_path,
    )
