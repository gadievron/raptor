"""Tests for ``render_scan_coverage`` — the operator-facing
tool-execution coverage renderer that fires at /scan end."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


class TestFindingsByTool:
    def test_findings_by_tool_preferred_over_heuristic(self, tmp_path):
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep", "rules_applied": 2,
        })
        _write(tmp_path, "coverage-coccinelle.json", {
            "tool": "coccinelle", "rules_applied": 1,
        })
        _write(tmp_path, "coverage-codeql.json", {
            "tool": "codeql", "rules_applied": 3,
        })
        _write(tmp_path, "scan_metrics.json", {
            "findings_by_tool": {
                "semgrep": 10,
                "coccinelle": 3,
                "codeql": 7,
            },
            "findings_by_rule": {
                "custom_rule_no_dots": 3,
                "engine.semgrep.rules.foo": 10,
                "cpp/something": 7,
            },
        })
        out = render_scan_coverage(tmp_path)
        assert "10 findings" in out
        assert " 3 findings" in out
        assert " 7 findings" in out

    def test_falls_back_to_heuristic_without_findings_by_tool(self, tmp_path):
        _write(tmp_path, "coverage-semgrep.json", {
            "tool": "semgrep", "rules_applied": 1,
        })
        _write(tmp_path, "scan_metrics.json", {
            "findings_by_rule": {
                "engine.semgrep.rules.foo": 5,
            },
        })
        out = render_scan_coverage(tmp_path)
        assert "5 findings" in out


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


@pytest.mark.parametrize('metrics,status', [
    ({}, 'ok'),
    ({'execution_status': 'ok'}, 'ok'),
    ({'execution_status': 'error'}, 'error'),
    ({'execution_status': 'partial'}, 'partial'),
    ({'execution_status': 'unknown'}, 'partial'),
    ({'execution_status': None}, 'partial'),
    ({'execution_status': []}, 'partial'),
    ({'semgrep_failed_packs': ['a']}, 'partial'),
    ({'dropped_registry_packs': ['a']}, 'partial'),
    ({'sarif_merge_failed': True}, 'partial'),
    ({'analysis_gaps': {'timeout': 1}}, 'partial'),
    ({'semgrep_dropped_files': 1}, 'partial'),
    ({'codeql_no_output': True}, 'partial'),
    ({'tool_execution_failures': {'coccinelle': 1}}, 'partial'),
    ({'tool_coverage_limitations': {'compiler': 2}}, 'partial'),
    ({'sarif_input_errors': 1}, 'partial'),
    ({'semgrep_metadata_errors': 1}, 'partial'),
    ({'semgrep_partial_files': 1}, 'partial'),
    ({'execution_status': 'ok', 'semgrep_failed_packs': ['a']}, 'partial'),
    ({'execution_status': 'error', 'sarif_merge_failed': True}, 'error'),
])
def test_known_execution_failures_prevent_success_summary(tmp_path, metrics, status):
    from core.reporting.scan_coverage import scan_execution_status
    assert scan_execution_status(metrics) == status
    _write(tmp_path, 'scan_metrics.json', metrics)
    rendered = render_scan_coverage(tmp_path)
    if metrics:
        assert rendered.startswith(f'Scan execution: {status}')
    else:
        assert rendered is None



def test_execution_summary_retains_diagnostics_without_coverage_files(tmp_path):
    _write(tmp_path, 'scan_metrics.json', {
        'tool_execution_failures': {'coccinelle': 1},
        'tool_coverage_limitations': {'compiler': 2},
        'sarif_input_errors': 3,
    })
    assert render_scan_coverage(tmp_path) == (
        'Scan execution: partial (1 failed tool invocation(s); '
        '2 coverage limitation(s); 3 report issue(s))'
    )


@pytest.mark.parametrize('counts', [{}, {'semgrep': 0}, {'semgrep': True}, {'semgrep': -1}, {'semgrep': '9'}])
def test_authoritative_tool_counts_do_not_fall_back_to_rule_names(tmp_path, counts):
    _write(tmp_path, 'coverage-semgrep.json', {'tool': 'semgrep'})
    _write(tmp_path, 'scan_metrics.json', {
        'findings_by_tool': counts,
        'findings_by_rule': {'engine.semgrep.example': 9},
    })
    assert '0 findings' in render_scan_coverage(tmp_path)


@pytest.mark.parametrize('malformed', [[], 'invalid', 42, False])
def test_malformed_record_cannot_hide_sibling_or_execution_summary(tmp_path, malformed):
    _write(tmp_path, 'coverage-semgrep.json', malformed)
    _write(tmp_path, 'coverage-codeql.json', {'tool': 'codeql'})
    _write(tmp_path, 'scan_metrics.json', {'execution_status': 'partial'})
    text = render_scan_coverage(tmp_path)
    assert 'CodeQL' in text
    assert 'Semgrep' not in text
    assert 'Scan execution: partial' in text


def test_tool_issue_paths_are_visible_once_without_echoing_diagnostics(tmp_path):
    _write(tmp_path, 'coverage-codeql.json', {
        'tool': 'codeql',
        'rules_applied': ['java/example', 'java/example', '', None, {}],
        'files_failed': [
            {'path': 'src/A.java', 'reason': 'private diagnostic'},
            {'path': 'src/A.java', 'reason': 'second issue'},
            {'path': 'src/B.java', 'reason': 'third issue'},
            {'path': ''}, None, {'path': []},
        ],
    })
    text = render_scan_coverage(tmp_path)
    assert '2 path(s) with tool warnings or errors' in text
    assert '1 rule group' in text
    assert 'private diagnostic' not in text


@pytest.mark.parametrize('rules', [[], 'invalid', 42, False, {'example': True}, {'example': -2}])
def test_malformed_legacy_rule_counts_are_not_reported_as_findings(tmp_path, rules):
    _write(tmp_path, 'coverage-codeql.json', {'tool': 'codeql'})
    _write(tmp_path, 'scan_metrics.json', {'findings_by_rule': rules})
    assert '0 findings' in render_scan_coverage(tmp_path)


def test_malformed_failed_packs_do_not_break_summary(tmp_path):
    _write(tmp_path, 'coverage-semgrep.json', {'tool': 'semgrep'})
    _write(tmp_path, 'scan_metrics.json', {'semgrep_failed_packs': ['pack', {}, None, 'pack']})
    assert '1 pack(s) failed: pack' in render_scan_coverage(tmp_path)


@pytest.mark.parametrize('snapshot', [{}, [], None, {'semgrep': []}])
def test_present_snapshot_never_resurrects_old_coverage_files(tmp_path, monkeypatch, snapshot):
    import core.reporting.scan_coverage as coverage
    _write(tmp_path, 'coverage-semgrep.json', {'tool': 'semgrep', 'rules_applied': 999})
    _write(tmp_path, 'scan_metrics.json', {'tool_coverage': snapshot, 'execution_status': 'ok'})
    def forbidden(*args):
        pytest.fail('modern summary must not reopen historical coverage records')
    monkeypatch.setattr(coverage, '_load_coverage_record', forbidden)
    assert render_scan_coverage(tmp_path) == 'Scan execution: ok'


def test_snapshot_replays_counts_without_full_coverage_records(tmp_path):
    from core.reporting.scan_coverage import summarize_tool_coverage
    record = {'tool': 'codeql', 'files_examined': ['private/path.java'],
              'rules_applied': ['java/example', 'java/example'],
              'files_failed': [{'path': 'private/path.java', 'reason': 'private diagnostic'}]}
    snapshot = summarize_tool_coverage(record)
    assert snapshot == {'rules_applied': 1, 'paths_with_issues': 1}
    assert summarize_tool_coverage(snapshot) == snapshot
    _write(tmp_path, 'scan_metrics.json', {
        'tool_coverage': {'codeql': snapshot}, 'findings_by_tool': {'codeql': 2},
    })
    text = render_scan_coverage(tmp_path)
    assert 'CodeQL' in text and '2 findings' in text
    assert '1 rule group' in text and '1 path(s) with tool warnings or errors' in text
    assert 'private/' not in text and 'private diagnostic' not in text
