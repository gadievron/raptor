"""Tests for the record-only sanitizer-cut scan post-pass."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")

from core.analysis.sanitizer_cut_postpass import (  # noqa: E402
    _candidate_source_lines,
    _locate_unique_source_line,
    run_postpass,
)
from core.testing.treesitter import requires_ts  # noqa: E402

_SAFE_JAVA = """import org.owasp.encoder.Encode;
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

_UNSAFE_JAVA = """import javax.servlet.http.HttpServletRequest;
import java.io.PrintWriter;
public class Test {
    void doPost(HttpServletRequest request, PrintWriter out) {
        String p = request.getParameter("q");
        out.println(p);
    }
}
"""

_AMBIGUOUS_JAVA = """import org.owasp.encoder.Encode;
import javax.servlet.http.HttpServletRequest;
import java.io.PrintWriter;
public class Test {
    void doPost(HttpServletRequest request, PrintWriter out) {
        String a = request.getParameter("a");
        String b = request.getParameter("b");
        String safe = Encode.forHtml(a);
        out.println(safe);
    }
}
"""


def _sarif(src: Path, *, cwe: str = "cwe-79", sink_line: int = 8,
           rule_id: str = "xss-rule") -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Semgrep OSS",
                "rules": [{
                    "id": rule_id,
                    "properties": {"tags": [f"external/cwe/{cwe}"]},
                }],
            }},
            "results": [{
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": "finding"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": str(src)},
                    "region": {"startLine": sink_line,
                               "endLine": sink_line},
                }}],
            }],
        }],
    }


def _write(tmp_path: Path, source: str, sarif_kwargs: dict | None = None):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    src = repo / "Test.java"
    src.write_text(source)
    sarif_path = tmp_path / "scan.sarif"
    sarif_path.write_text(json.dumps(_sarif(src, **(sarif_kwargs or {}))))
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return repo, src, sarif_path, out


class TestVerdictRecording:
    def test_encoder_guarded_finding_records_suppress(self, tmp_path):
        # Re-pinned 2026-08-19: enforcement is the corpus-earned,
        # operator-approved default — a full-proof suppress verdict now
        # records dropped: true and its identity for the scanner filter.
        repo, _, sarif_path, out = _write(tmp_path, _SAFE_JAVA)
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        assert stats["recorded_suppress"] == 1
        assert stats["enforced"] == 1
        assert len(stats["enforced_findings"]) == 1
        records = [
            json.loads(line)
            for line in (out / "suppressions.jsonl").read_text().splitlines()
        ]
        assert len(records) == 1
        assert records[0]["verdict"] == "sanitizer_dominated"
        assert records[0]["dropped"] is True
        assert records[0]["enforced"] is True

    def test_record_only_mode_still_available(self, tmp_path):
        # The pre-flip contract survives behind enforce=False (the
        # scanner's --no-sanitizer-cut-enforce path): evidence only.
        repo, _, sarif_path, out = _write(tmp_path, _SAFE_JAVA)
        stats = run_postpass([sarif_path], repo, out, enforce=False)
        assert stats["recorded_suppress"] == 1
        assert stats["enforced"] == 0
        assert stats["enforced_findings"] == []
        records = [
            json.loads(line)
            for line in (out / "suppressions.jsonl").read_text().splitlines()
        ]
        assert records[0]["dropped"] is False
        assert records[0]["enforced"] is False

    def test_enforcement_bounded_by_spec(self, tmp_path, monkeypatch):
        # enforce=True can never exceed the earning contract: with the
        # spec reverted (the one-field rollback), the same call records
        # evidence only. Guards the reversibility promise.
        import dataclasses
        import core.analysis.reach_witness as rw
        reverted = dataclasses.replace(
            rw.VERDICTS["sanitizer_dominated"], earns_suppression=False,
        )
        monkeypatch.setitem(rw.VERDICTS, "sanitizer_dominated", reverted)
        repo, _, sarif_path, out = _write(tmp_path, _SAFE_JAVA)
        stats = run_postpass([sarif_path], repo, out, enforce=True)
        assert stats["recorded_suppress"] == 1
        assert stats["enforced"] == 0
        records = [
            json.loads(line)
            for line in (out / "suppressions.jsonl").read_text().splitlines()
        ]
        assert records[0]["dropped"] is False

    @requires_ts("java")
    def test_unsanitized_finding_records_nothing(self, tmp_path):
        repo, _, sarif_path, out = _write(
            tmp_path, _UNSAFE_JAVA, {"sink_line": 6},
        )
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        assert stats["recorded_suppress"] == 0
        assert stats["refused_reasons"].get("no-suppress-verdict") == 1
        assert not (out / "suppressions.jsonl").exists()

    def test_never_mutates_inputs(self, tmp_path):
        repo, src, sarif_path, out = _write(tmp_path, _SAFE_JAVA)
        sarif_before = sarif_path.read_bytes()
        src_before = src.read_bytes()
        run_postpass([sarif_path], repo, out)
        assert sarif_path.read_bytes() == sarif_before
        assert src.read_bytes() == src_before


class TestSourceLocator:
    @requires_ts("java")
    def test_multi_source_all_must_suppress(self, tmp_path):
        # Two candidate sources: the flow from `a` is encoded
        # (suppress) but `b` never reaches the sanitizer input
        # (candidate_only) — the finding counts as candidate, no
        # suppress verdict is recorded.
        repo, _, sarif_path, out = _write(
            tmp_path, _AMBIGUOUS_JAVA, {"sink_line": 9},
        )
        stats = run_postpass([sarif_path], repo, out)
        assert stats["recorded_suppress"] == 0
        assert stats["recorded_candidate"] == 1
        assert not (out / "suppressions.jsonl").exists()

    def test_locator_unique_before_sink(self, tmp_path):
        f = tmp_path / "T.java"
        f.write_text(
            'a\nString p = req.getParameter("x");\nc\nsink\n'
            'String q = req.getParameter("y");\n'
        )
        cache: dict = {}
        assert _locate_unique_source_line(f, 4, "java", cache) == 2
        # both before the sink → not unique, but both are candidates
        assert _locate_unique_source_line(f, 6, "java", cache) is None
        assert _candidate_source_lines(f, 6, "java", cache) == [2, 5]

    def test_dataflow_source_preferred_over_locator(self, tmp_path):
        # Ambiguous file sources, but the SARIF carries codeFlows —
        # the trace's source line must win and the finding evaluates.
        repo = tmp_path / "repo"
        repo.mkdir()
        src = repo / "Test.java"
        src.write_text(_AMBIGUOUS_JAVA)
        sarif = _sarif(src, sink_line=9)
        result = sarif["runs"][0]["results"][0]
        result["codeFlows"] = [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": str(src)},
                "region": {"startLine": 6}}}},
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": str(src)},
                "region": {"startLine": 9}}}},
        ]}]}]
        sarif_path = tmp_path / "scan.sarif"
        sarif_path.write_text(json.dumps(sarif))
        out = tmp_path / "out"
        out.mkdir()
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        # the trace line short-circuits the locator: one candidate only
        assert stats["refused_reasons"].get("no-source-candidates") is None


class TestGating:
    def test_catalog_empty_java_class_examined(self, tmp_path):
        # b21 reverses the old skip: CWE-89 java has an empty catalog
        # (PreparedStatement is structural), but the constant-definers
        # and collection-guard pre-checks suppress WITHOUT call-shaped
        # sanitizers — java findings are examined regardless of
        # catalog coverage. Non-java catalog-empty classes still skip
        # (test_unsupported_language_skipped pins the language gate).
        repo, _, sarif_path, out = _write(
            tmp_path, _SAFE_JAVA, {"cwe": "cwe-89", "rule_id": "sqli"},
        )
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1

    def test_unsupported_language_skipped(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        src = repo / "t.js"
        src.write_text("sink(x);\n")
        sarif_path = tmp_path / "scan.sarif"
        sarif_path.write_text(json.dumps(_sarif(src, sink_line=1)))
        out = tmp_path / "out"
        out.mkdir()
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 0

    def test_file_outside_target_refused(self, tmp_path):
        repo, src, sarif_path, out = _write(tmp_path, _SAFE_JAVA)
        outside = tmp_path / "elsewhere.java"
        outside.write_text(_SAFE_JAVA)
        sarif_path.write_text(json.dumps(_sarif(outside)))
        stats = run_postpass([sarif_path], repo, out)
        assert stats["refused_reasons"].get(
            "file-outside-target-or-missing") == 1
        assert not (out / "suppressions.jsonl").exists()


class TestBudget:
    def test_zero_budget_skips_everything(self, tmp_path):
        repo, _, sarif_path, out = _write(tmp_path, _SAFE_JAVA)
        stats = run_postpass([sarif_path], repo, out, budget_seconds=0.0)
        assert stats["budget_exhausted_skips"] == 1
        assert stats["examined"] == 0
        assert not (out / "suppressions.jsonl").exists()


class TestScannerWiring:
    def test_flag_and_gate_present(self):
        src = (
            Path(__file__).resolve().parents[3]
            / "packages" / "static-analysis" / "scanner.py"
        ).read_text()
        assert '"--no-sanitizer-cut-postpass"' in src
        assert "SANITIZER_CUT_POSTPASS_ENABLED" in src
        assert "not args.no_sanitizer_cut_postpass" in src

    def test_config_default_on(self):
        from core.config import RaptorConfig
        assert RaptorConfig.SANITIZER_CUT_POSTPASS_ENABLED is True


class TestConstantGate:
    _TRICK = """import javax.servlet.http.HttpServletRequest;
public class Test {
    void doPost(HttpServletRequest request, java.io.PrintWriter out) {
        String param = request.getParameter("q");
        int num = 106;
        String bar = (7 * 18) + num > 200 ? "safe" : param;
        out.println(bar);
    }
}
"""

    @requires_ts("java")
    def test_dead_branch_ternary_suppresses_via_constancy(self, tmp_path):
        repo, _, sarif_path, out = _write(
            tmp_path, self._TRICK, {"sink_line": 7},
        )
        stats = run_postpass([sarif_path], repo, out)
        assert stats["recorded_suppress"] == 1
        import json as _json
        rec = _json.loads(
            (out / "suppressions.jsonl").read_text().splitlines()[0],
        )
        assert "constant sink argument" in rec["reason"]
        # Re-pinned 2026-08-19: full-proof suppress verdicts enforce by
        # default (corpus-earned, operator-approved).
        assert rec["dropped"] is True

    def test_sibling_arg_inversion_never_suppresses(self, tmp_path):
        src = """import javax.servlet.http.HttpServletRequest;
public class Test {
    void doPost(HttpServletRequest request, java.io.PrintWriter out) {
        String zz = request.getParameter("q");
        String aa = "constant";
        out.printf(aa, zz);
    }
}
"""
        repo, _, sarif_path, out = _write(tmp_path, src, {"sink_line": 6})
        stats = run_postpass([sarif_path], repo, out)
        assert stats["recorded_suppress"] == 0


class TestGrammarAbsentDegradation:
    """Hermetic parser-absent contract (audit-suite degradation
    doctrine): a missing java grammar must degrade LOUDLY — the
    finding lands in the enumerated ``language-unsupported`` refusal
    bucket and one warning names the missing capability. Silent
    fold-in with ``resolver-refused`` would make degraded coverage
    indistinguishable from full coverage."""

    def test_java_grammar_absent_refuses_loudly(
            self, tmp_path, monkeypatch, caplog):
        import logging

        import core.analysis.cfg_builder_java as cbj

        monkeypatch.setattr(cbj, "_get_parser", lambda: None)
        repo, _, sarif_path, out = _write(tmp_path, _SAFE_JAVA)
        with caplog.at_level(
                logging.WARNING, logger="core.analysis.sanitizer_cut_postpass"):
            stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        assert stats["recorded_suppress"] == 0
        assert stats["refused_reasons"].get("language-unsupported") == 1
        assert not (out / "suppressions.jsonl").exists()
        warnings = [r.message for r in caplog.records
                    if "grammar not installed" in r.message]
        assert len(warnings) == 1  # once per run, not per finding

    def test_python_leg_needs_no_grammar(self, tmp_path, monkeypatch):
        """The stdlib-ast python leg must be untouched by the probe."""
        import core.analysis.cfg_builder_java as cbj

        monkeypatch.setattr(cbj, "_get_parser", lambda: None)
        repo = tmp_path / "repo"
        repo.mkdir()
        src = repo / "app.py"
        src.write_text(
            "def handle():\n"
            "    x = request.args.get('q')\n"
            "    y = html.escape(x)\n"
            "    render(y)\n",
            encoding="utf-8",
        )
        sarif_path = tmp_path / "scan.sarif"
        sarif_path.write_text(json.dumps(_sarif(src, sink_line=4)))
        out = tmp_path / "out"
        out.mkdir()
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        assert stats["refused_reasons"].get("language-unsupported") is None
        assert stats["recorded_suppress"] == 1


_WRAPPER_SOURCE_JAVA = """import org.owasp.encoder.Encode;
import java.io.PrintWriter;
public class Test {
    void doPost(Helper scr, PrintWriter out) {
        String p = scr.getTheParameter("q");
        String safe = Encode.forHtml(p);
        out.println(safe);
    }
}
"""


class TestLearnedSourcePatterns:
    """Run-scoped learned wrapper names extend the source locator."""

    def test_wrapper_source_refused_without_learned_names(self, tmp_path):
        repo, _, sarif_path, out = _write(
            tmp_path, _WRAPPER_SOURCE_JAVA, {"sink_line": 7},
        )
        stats = run_postpass([sarif_path], repo, out)
        assert stats["refused_reasons"].get("no-source-candidates") == 1
        assert stats["recorded_suppress"] == 0

    def test_wrapper_source_examined_with_learned_names(self, tmp_path):
        repo, _, sarif_path, out = _write(
            tmp_path, _WRAPPER_SOURCE_JAVA, {"sink_line": 7},
        )
        stats = run_postpass(
            [sarif_path], repo, out,
            extra_source_patterns=["getTheParameter"],
        )
        assert stats["refused_reasons"].get("no-source-candidates") is None
        assert stats["recorded_suppress"] == 1
        assert stats["mechanism_counts"]["learned-source-patterns"] == 1

    def test_invalid_learned_names_dropped_not_compiled(self, tmp_path):
        from core.analysis.sanitizer_cut_postpass import (
            _compile_extra_source_patterns,
        )
        pats = _compile_extra_source_patterns(
            ["ok_name", "bad name", "get(", "", None, "x" * 200],
        )
        assert pats == (r"\.ok_name\s*\(",)

    def test_default_behavior_unchanged_without_names(self, tmp_path):
        repo, _, sarif_path, out = _write(tmp_path, _SAFE_JAVA)
        base = run_postpass([sarif_path], repo, out)
        assert "learned-source-patterns" not in base["mechanism_counts"]


_ENV_SOURCE_JAVA = """public class Test {
    void run() {
        String data = System.getenv("ADD");
        java.io.File f = new java.io.File(data);
    }
}
"""

_ENV_UNION_JAVA = """public class Test {
    private boolean flag = false;
    void run() {
        String data;
        if (flag) {
            data = System.getenv("ADD");
        } else {
            data = null;
        }
        java.io.File f = new java.io.File(data);
    }
}
"""

_SEPARATOR_UNION_JAVA = """import javax.servlet.http.HttpServletRequest;
public class Test {
    void doPost(HttpServletRequest request) throws Exception {
        String p = request.getParameter("q");
        String data;
        if (p.length() > 2) {
            data = java.io.File.separator;
        } else {
            data = "opt";
        }
        new java.io.FileInputStream(data);
    }
}
"""


class TestTfSystemReadBan:
    """b42 circularity ban: when a finding's own candidate sources
    include a system-read kind, taint-freedom must not discharge such
    reads — measured live as 17 Juliet ground-truth-bad
    environment-source findings suppressed via the TF tier, invisible
    to the damage metric because the records carried no line."""

    def test_env_source_finding_never_suppresses(self, tmp_path):
        repo, _, sarif_path, out = _write(
            tmp_path, _ENV_SOURCE_JAVA,
            {"cwe": "cwe-22", "sink_line": 4, "rule_id": "pathtrav"},
        )
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        assert stats["recorded_suppress"] == 0
        assert not (out / "suppressions.jsonl").exists()
        assert stats["mechanism_counts"].get(
            "taint-free:banned-system-read-source") == 1

    def test_env_union_finding_never_suppresses(self, tmp_path):
        # The b42 union must not resurrect the suppression either:
        # {getenv, null} unions to taint-free ONLY where getenv is not
        # this finding's suspected source.
        repo, _, sarif_path, out = _write(
            tmp_path, _ENV_UNION_JAVA,
            {"cwe": "cwe-22", "sink_line": 10, "rule_id": "pathtrav"},
        )
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        assert stats["recorded_suppress"] == 0

    def test_non_source_tf_union_still_suppresses(self, tmp_path):
        # File.separator is never a locator source kind: a servlet-
        # source finding whose sink value unions {separator, "/opt"}
        # keeps the taint-free suppression.
        repo, _, sarif_path, out = _write(
            tmp_path, _SEPARATOR_UNION_JAVA,
            {"cwe": "cwe-22", "sink_line": 11, "rule_id": "pathtrav"},
        )
        stats = run_postpass([sarif_path], repo, out)
        assert stats["examined"] == 1
        assert stats["recorded_suppress"] == 1
        records = [
            json.loads(line)
            for line in (out / "suppressions.jsonl").read_text().splitlines()
        ]
        # b42 record-line fix: the record must place itself at the
        # sink so line-scoped ground-truth entries can match it.
        assert records[0]["line"] == 11


class TestEnforcementBoundaries:
    """The flip's structural safety pins (operator-approved
    2026-08-19): candidates can never enforce; the SARIF filter is
    conservative and no-op-on-failure."""

    def test_candidate_only_never_enforces(self, tmp_path):
        # A candidate_only verdict must record dropped: false even with
        # enforcement on — the enforce=True call is structurally
        # reachable only from the full-proof suppress branch.
        src = """import javax.servlet.http.HttpServletRequest;
import org.owasp.encoder.Encode;
public class Test {
    void doPost(HttpServletRequest request, java.io.PrintWriter out) {
        String p = request.getParameter("q");
        String[] arr = new String[2];
        arr[0] = Encode.forHtml(p);
        out.println(arr[0]);
    }
}
"""
        repo, _, sarif_path, out = _write(tmp_path, src, {"sink_line": 8})
        stats = run_postpass([sarif_path], repo, out, enforce=True)
        if stats["recorded_candidate"]:
            import json as _json
            recs = [
                _json.loads(line) for line in
                (out / "suppressions.jsonl").read_text().splitlines()
            ]
            assert all(r["dropped"] is False for r in recs)
            assert all(r["enforced"] is False for r in recs)
        assert stats["enforced_findings"] == [] or stats["enforced"] == len(
            stats["enforced_findings"])

    def test_filter_removes_exact_match_only(self, tmp_path):
        import json as _json
        from core.analysis.sanitizer_cut_postpass import (
            filter_enforced_from_sarif,
        )
        sarif = tmp_path / "combined.sarif"
        results = [
            {"ruleId": "r1", "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/A.java"},
                "region": {"startLine": 8}}}]},
            {"ruleId": "r1", "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/A.java"},
                "region": {"startLine": 9}}}]},
            {"ruleId": "r2", "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/A.java"},
                "region": {"startLine": 8}}}]},
        ]
        sarif.write_text(_json.dumps(
            {"runs": [{"results": results}]}), encoding="utf-8")
        removed = filter_enforced_from_sarif(
            sarif, [{"rule_id": "r1", "file": "src/A.java", "line": 8}])
        assert removed == 1
        kept = _json.loads(sarif.read_text())["runs"][0]["results"]
        assert len(kept) == 2
        assert {(r["ruleId"],
                 r["locations"][0]["physicalLocation"]["region"]["startLine"])
                for r in kept} == {("r1", 9), ("r2", 8)}

    def test_filter_noop_on_malformed_sarif(self, tmp_path):
        from core.analysis.sanitizer_cut_postpass import (
            filter_enforced_from_sarif,
        )
        sarif = tmp_path / "combined.sarif"
        sarif.write_text("not json", encoding="utf-8")
        assert filter_enforced_from_sarif(
            sarif, [{"rule_id": "r", "file": "f", "line": 1}]) == 0
        assert sarif.read_text() == "not json"

    def test_filter_empty_enforced_is_noop(self, tmp_path):
        from core.analysis.sanitizer_cut_postpass import (
            filter_enforced_from_sarif,
        )
        sarif = tmp_path / "combined.sarif"
        sarif.write_text("{}", encoding="utf-8")
        assert filter_enforced_from_sarif(sarif, []) == 0
