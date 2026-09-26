"""Same-file guard on the postpass's trace-anchored evaluation.

A dataflow trace's source line is only meaningful in the file the
trace reported it against. The postpass evaluates the value-bound
gate against the SINK file's text, so a cross-file trace (source step
file != finding file) previously classified the wrong file's lines —
and could false-suppress a real cross-file flow whenever the foreign
line number happened to land on a source-then-sanitized line of the
sink file. Cross-file traces now skip the evaluation with an
enumerated refusal; same-file traces keep the exact trace behavior.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")

from core.analysis.sanitizer_cut_postpass import (  # noqa: E402
    _dataflow_source_file,
    _trace_source_is_cross_file,
    run_postpass,
)
from core.testing.treesitter import requires_ts  # noqa: E402

#: Sink file whose line 6 is a getParameter call that flows through
#: an encoder — a same-file trace anchored at line 6 suppresses.
_SINK_JAVA = """import org.owasp.encoder.Encode;
import javax.servlet.http.HttpServletRequest;
import java.io.PrintWriter;
public class Test {
    void doPost(HttpServletRequest request, PrintWriter out) {
        String p = request.getParameter("q");
        String safe = Encode.forHtml(p);
        out.println(safe);
    }
}
"""

#: The REAL source of the cross-file flow — a different file whose
#: line 6 is where the tainted value enters. Its value never meets
#: the sink file's encoder.
_SOURCE_JAVA = """import javax.servlet.http.HttpServletRequest;
public class Feed {
    private String held;
    void capture(HttpServletRequest request) {
        // line 5
        held = request.getParameter("raw");
    }
}
"""


def _sarif_with_trace(sink: Path, source: Path, *, source_line: int,
                      sink_line: int = 8) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Semgrep OSS",
                "rules": [{
                    "id": "xss-rule",
                    "properties": {"tags": ["external/cwe/cwe-79"]},
                }],
            }},
            "results": [{
                "ruleId": "xss-rule",
                "level": "warning",
                "message": {"text": "finding"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": str(sink)},
                    "region": {"startLine": sink_line,
                               "endLine": sink_line},
                }}],
                "codeFlows": [{"threadFlows": [{"locations": [
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": str(source)},
                        "region": {"startLine": source_line}}}},
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": str(sink)},
                        "region": {"startLine": sink_line}}}},
                ]}]}],
            }],
        }],
    }


def _setup(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    sink = repo / "Test.java"
    sink.write_text(_SINK_JAVA)
    source = repo / "Feed.java"
    source.write_text(_SOURCE_JAVA)
    out = tmp_path / "out"
    out.mkdir()
    return repo, sink, source, out


class TestCrossFileTraceRefused:
    @requires_ts("java")
    def test_cross_file_trace_would_have_false_suppressed(
            self, tmp_path):
        # The foreign source step's line (6) happens to land on the
        # sink file's own getParameter-then-encode line — exactly the
        # collision that previously evaluated the WRONG file's lines
        # and suppressed a real cross-file flow. The same-file guard
        # refuses instead; nothing is suppressed.
        repo, sink, source, out = _setup(tmp_path)
        sarif_path = tmp_path / "scan.sarif"
        sarif_path.write_text(json.dumps(
            _sarif_with_trace(sink, source, source_line=6)))
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        assert stats["refused_reasons"].get("trace-source-cross-file") == 1
        assert stats["recorded_suppress"] == 0
        assert stats["enforced"] == 0
        assert not (out / "suppressions.jsonl").exists()
        # The trace never counts as a source kind — the evaluation was
        # skipped, not silently retargeted at local candidates.
        assert "trace" not in stats["source_kind_counts"]

    @requires_ts("java")
    def test_same_file_trace_still_suppresses(self, tmp_path):
        # Two-direction: an intra-file trace anchored at the sink
        # file's own source line keeps the pre-existing suppression.
        repo, sink, _, out = _setup(tmp_path)
        sarif_path = tmp_path / "scan.sarif"
        sarif_path.write_text(json.dumps(
            _sarif_with_trace(sink, sink, source_line=6)))
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        assert stats["source_kind_counts"].get("trace") == 1
        assert stats["recorded_suppress"] == 1
        assert stats["refused_reasons"].get(
            "trace-source-cross-file") is None

    @requires_ts("java")
    def test_line_only_trace_keeps_same_file_assumption(self, tmp_path):
        # A trace whose source step names no file (empty string, the
        # producer's honest-empty form) keeps the pre-existing
        # behavior: the line anchors in the sink file.
        repo, sink, _, out = _setup(tmp_path)
        sarif = _sarif_with_trace(sink, sink, source_line=6)
        flow_locs = (sarif["runs"][0]["results"][0]["codeFlows"][0]
                     ["threadFlows"][0]["locations"])
        flow_locs[0]["location"]["physicalLocation"][
            "artifactLocation"]["uri"] = ""
        sarif_path = tmp_path / "scan.sarif"
        sarif_path.write_text(json.dumps(sarif))
        stats = run_postpass([sarif_path], repo, out)
        # Empty-uri source step: parse drops the file (empty string);
        # the guard does not fire and the trace line evaluates as
        # before.
        assert stats["refused_reasons"].get(
            "trace-source-cross-file") is None
        assert stats["source_kind_counts"].get("trace") == 1


class TestHelpers:
    def test_source_file_read(self):
        finding = {"dataflow_path": {"source": {"file": "a.java",
                                                "line": 3}}}
        assert _dataflow_source_file(finding) == "a.java"

    def test_non_string_file_is_empty(self):
        assert _dataflow_source_file(
            {"dataflow_path": {"source": {"file": 42}}}) == ""
        assert _dataflow_source_file({}) == ""

    def test_relative_trace_file_resolved_against_repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        sink = repo / "Test.java"
        sink.write_text("x\n")
        assert _trace_source_is_cross_file(
            "Test.java", sink, repo) is False
        other = repo / "Other.java"
        other.write_text("y\n")
        assert _trace_source_is_cross_file(
            "Other.java", sink, repo) is True

    def test_unresolvable_path_counts_as_cross_file(self, tmp_path):
        # Refusal direction: a path that cannot resolve must never
        # anchor a suppression.
        repo = tmp_path / "repo"
        repo.mkdir()
        sink = repo / "Test.java"
        sink.write_text("x\n")
        assert _trace_source_is_cross_file(
            "\x00bad", sink, repo) is True
