"""Tests for ``render_scan_coverage`` — the operator-facing
tool-execution coverage renderer that fires at /scan end."""

from __future__ import annotations

import json
from pathlib import Path

from core.reporting.scan_coverage import render_scan_coverage


def _write(out_dir: Path, name: str, payload):
    (out_dir / name).write_text(json.dumps(payload))


class TestMissingFiles:
    def test_no_coverage_files_returns_none(self, tmp_path):
        # Empty dir → no tools ran → caller suppresses the section.
        assert render_scan_coverage(tmp_path) is None

    def test_missing_scan_metrics_still_renders(self, tmp_path):
        # Coverage file exists but no scan_metrics.json — falls back
        # to ''0 findings'' but still renders the line so the
        # operator sees the tool ran.
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep", "files_examined": 10, "rules_applied": 3,
        })
        out = render_scan_coverage(tmp_path)
        assert out is not None
        assert "Semgrep" in out


class TestSingleTool:
    def test_semgrep_only(self, tmp_path):
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep", "files_examined": 100, "rules_applied": 3,
        })
        _write(tmp_path, "scan_metrics.json", {
            "total_findings": 47,
            "findings_by_rule": {
                "engine.semgrep.rules.registry-cache.c.lang.security.foo": 45,
                "engine.semgrep.rules.registry-cache.c.lang.security.bar": 2,
            },
        })
        out = render_scan_coverage(tmp_path)
        assert out is not None
        assert "Coverage:" in out
        assert "Semgrep" in out
        # 47 findings attributed to semgrep via rule-id prefix match.
        assert "47 findings" in out
        assert "3 rule groups" in out

    def test_coccinelle_only(self, tmp_path):
        _write(tmp_path, "coverage-coccinelle.json", {
            "tool": "coccinelle", "files_examined": 50, "rules_applied": 3,
        })
        _write(tmp_path, "scan_metrics.json", {
            "total_findings": 0,
            "findings_by_rule": {},
        })
        out = render_scan_coverage(tmp_path)
        assert "Coccinelle" in out
        assert "0 findings" in out
        assert "3 rule groups" in out


class TestMultiTool:
    def test_three_tools_aligned(self, tmp_path):
        # All three tools present; Semgrep + Coccinelle ran with
        # different result shapes.
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep", "rules_applied": 3,
        })
        _write(tmp_path, "coverage-coccinelle.json", {
            "tool": "coccinelle", "rules_applied": 3,
        })
        _write(tmp_path, "coverage-codeql.json", {
            "tool": "codeql", "rules_applied": 8,
        })
        _write(tmp_path, "scan_metrics.json", {
            "findings_by_rule": {
                "engine.semgrep.rules.registry-cache.foo": 47,
                "cpp/uncontrolled-format-string": 5,
            },
        })
        out = render_scan_coverage(tmp_path)
        assert out is not None
        # All three tools rendered, in canonical order.
        sem_pos = out.find("Semgrep")
        cocci_pos = out.find("Coccinelle")
        codeql_pos = out.find("CodeQL")
        assert sem_pos < cocci_pos < codeql_pos
        # Coccinelle ran but found nothing.
        assert "0 finding" in out
        # CodeQL findings attributed via lang/rule-id prefix match.
        assert "5 findings" in out

    def test_indentation_aligns_tool_labels(self, tmp_path):
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep", "rules_applied": 1,
        })
        _write(tmp_path, "coverage-coccinelle.json", {
            "tool": "coccinelle", "rules_applied": 1,
        })
        out = render_scan_coverage(tmp_path)
        # First line has ``Coverage: ``; second is indented by 10
        # spaces so tool labels align vertically.
        lines = out.splitlines()
        assert lines[0].startswith("Coverage: ")
        assert lines[1].startswith(" " * len("Coverage: "))


class TestSemgrepFailedPacks:
    def test_failed_packs_show_warning(self, tmp_path):
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep", "rules_applied": 3,
        })
        _write(tmp_path, "scan_metrics.json", {
            "findings_by_rule": {},
            "semgrep_failed_packs": [
                "semgrep_owasp_top_10", "semgrep_secrets",
            ],
        })
        out = render_scan_coverage(tmp_path)
        assert "⚠️" in out
        assert "2 pack(s) failed" in out
        assert "semgrep_owasp_top_10" in out

    def test_empty_failed_packs_no_warning(self, tmp_path):
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep", "rules_applied": 3,
        })
        _write(tmp_path, "scan_metrics.json", {
            "findings_by_rule": {},
            "semgrep_failed_packs": [],  # positive empty marker
        })
        out = render_scan_coverage(tmp_path)
        assert "⚠️" not in out
        assert "failed" not in out.lower()


class TestRobustness:
    def test_malformed_coverage_file_skipped(self, tmp_path):
        # Garbage JSON in one file → that tool's line is skipped;
        # other tools still render.
        (tmp_path / "coverage-semgrep.json").write_text("not-json{")
        _write(tmp_path, "coverage-coccinelle.json", {
            "tool": "coccinelle", "rules_applied": 1,
        })
        out = render_scan_coverage(tmp_path)
        assert out is not None
        assert "Coccinelle" in out
        assert "Semgrep" not in out

    def test_legacy_rules_applied_as_list(self, tmp_path):
        # Pre-rules_applied-as-int era: list of rule names.
        # Counted by length.
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep",
            "rules_applied": ["rule_a", "rule_b", "rule_c", "rule_d"],
        })
        out = render_scan_coverage(tmp_path)
        assert "4 rule groups" in out

    def test_singular_grammar_for_one_rule_and_one_finding(self, tmp_path):
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep", "rules_applied": 1,
        })
        _write(tmp_path, "scan_metrics.json", {
            "findings_by_rule": {
                "engine.semgrep.rules.registry-cache.foo": 1,
            },
        })
        out = render_scan_coverage(tmp_path)
        assert "1 finding " in out + " "  # singular ''finding''
        assert "1 rule group" in out      # singular ''rule group''
