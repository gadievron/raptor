"""Cross-method candidate scoping for the traceless reconstruction path.

Engine fact anchoring the scoping: a traceless finding reached the
reconstruction path because its producer's taint analysis is
intra-procedural (engines that cross methods emit dataflow traces, and
traces take the trace path). A source candidate OUTSIDE the sink's
enclosing method therefore cannot be the withheld trace's source —
excluding it is sound. Caller-mediated taint (a parameter feeding the
sink) needs no synthetic candidate: the gate's definer-exclusivity
condition is source-agnostic, so it blocks suppression under every
candidate — pinned below rather than re-implemented.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")

from core.analysis.cross_method_java import enclosing_method_span  # noqa: E402
from core.analysis.sanitizer_cut_postpass import run_postpass  # noqa: E402

# Source-shaped line in an UNRELATED method + fully sanitized sink
# method: pre-scoping this refused (resolver: no enclosing method for
# the cross-method candidate); post-scoping the sink method's own
# candidate suppresses and the unrelated one is scoped out.
_CROSS_METHOD_SAFE = """import org.owasp.encoder.Encode;
import javax.servlet.http.HttpServletRequest;
import java.io.PrintWriter;
public class Test {
    void unrelated(HttpServletRequest request) {
        String x = request.getParameter("other");
        System.err.println(x.length());
    }
    void doPost(HttpServletRequest request, PrintWriter out) {
        String p = request.getParameter("q");
        String safe = Encode.forHtml(p);
        out.println(safe);
    }
}
"""

# The sink argument concatenates a raw parameter alongside a fully-
# sanitized value: definer-exclusivity (condition 3) must block
# suppression under every candidate — caller-mediated taint cannot be
# suppressed regardless of candidate scoping.
_PARAM_FED_SINK = """import org.owasp.encoder.Encode;
import javax.servlet.http.HttpServletRequest;
import java.io.PrintWriter;
public class Test {
    void unrelated(HttpServletRequest request) {
        String x = request.getParameter("other");
        System.err.println(x.length());
    }
    void helper(HttpServletRequest request, String data, PrintWriter out) {
        String p = request.getParameter("q");
        String safe = Encode.forHtml(p);
        String msg = safe + data;
        out.println(msg);
    }
}
"""

# Zero same-method candidates after scoping -> no-source-candidates
# refusal (scoping must never manufacture suppressibility).
_NO_LOCAL_CANDIDATES = """import java.io.PrintWriter;
public class Test {
    void helper(String data, PrintWriter out) {
        out.println(data);
    }
}
"""


def _sarif(src: Path, *, cwe: str = "cwe-79", sink_line: int,
           rule_id: str = "xss-rule", trace_line: int | None = None) -> dict:
    result = {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": "finding"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": str(src)},
            "region": {"startLine": sink_line, "endLine": sink_line},
        }}],
    }
    if trace_line is not None:
        result["codeFlows"] = [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": str(src)},
                "region": {"startLine": trace_line},
            }}},
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": str(src)},
                "region": {"startLine": sink_line},
            }}},
        ]}]}]
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "CodeQL" if trace_line is not None else "Semgrep OSS",
                "rules": [{
                    "id": rule_id,
                    "properties": {"tags": [f"external/cwe/{cwe}"]},
                }],
            }},
            "results": [result],
        }],
    }


def _run(tmp_path: Path, source: str, **kwargs):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    src = repo / "Test.java"
    src.write_text(source)
    sarif_path = tmp_path / "scan.sarif"
    sarif_path.write_text(json.dumps(_sarif(src, **kwargs)))
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    stats = run_postpass([sarif_path], repo, out)
    return stats, out


class TestMethodSpan:
    def test_span_covers_method(self):
        name, start, end = enclosing_method_span(_CROSS_METHOD_SAFE, 11)
        assert name == "doPost"
        assert start <= 10 and end >= 12

    def test_no_method_returns_none(self):
        assert enclosing_method_span(_CROSS_METHOD_SAFE, 1) is None


class TestCrossMethodScoping:
    def test_cross_method_candidate_scoped_out_and_suppresses(self, tmp_path):
        stats, out = _run(tmp_path, _CROSS_METHOD_SAFE, sink_line=12)
        assert stats["recorded_suppress"] == 1
        assert stats["mechanism_counts"].get("cross-method:candidate-scoped", 0) >= 1
        assert (out / "suppressions.jsonl").exists()

    def test_params_entry_redundant_with_condition3(self, tmp_path):
        stats, out = _run(tmp_path, _PARAM_FED_SINK, sink_line=13)
        assert stats["recorded_suppress"] == 0
        # A candidate_only evidence record is fine; a suppress verdict
        # is the failure this test exists to catch.
        rec_file = out / "suppressions.jsonl"
        if rec_file.exists():
            for line in rec_file.read_text().splitlines():
                rec = json.loads(line)
                assert rec.get("verdict") != "suppress"

    def test_entry_alone_never_licenses_suppression(self, tmp_path):
        stats, out = _run(tmp_path, _NO_LOCAL_CANDIDATES, sink_line=4)
        assert stats["recorded_suppress"] == 0
        assert stats["refused_reasons"].get("no-source-candidates", 0) == 1

    def test_trace_cross_method_still_refuses(self, tmp_path):
        # Trace-carrying producers CAN cross methods: scoping must not
        # apply, and today's honest refusal stands.
        stats, out = _run(tmp_path, _CROSS_METHOD_SAFE, sink_line=12,
                          trace_line=6)
        assert stats["recorded_suppress"] == 0
        assert stats["refused_reasons"].get("resolver-refused", 0) == 1
