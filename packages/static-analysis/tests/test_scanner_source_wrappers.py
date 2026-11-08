"""Tests for the source-wrapper projection /scan stage.

Same hyphenated-package importlib pattern as the other scanner tests.
The semgrep runner and the summary scanner are faked throughout — no
semgrep binary or tree-sitter required.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# parents[3]: tests/ → static-analysis/ → packages/ → repo root
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if __name__ == "__main__":
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)

_SCANNER_PATH = Path(_REPO_ROOT) / "packages/static-analysis/scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_source_wrappers", _SCANNER_PATH,
)
_scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scanner)


class FakeSemgrepResult:
    def __init__(self, findings=(), errors=()):
        self.findings = list(findings)
        self.errors = list(errors)


def _wire_stage(monkeypatch, run_result):
    """Route the stage's lazy imports at fakes: one qualifying wrapper
    summary, a non-empty generated ruleset, and ``run_result`` from
    the semgrep runner."""
    summary = SimpleNamespace(name="getTheParameter")
    monkeypatch.setattr(
        "core.analysis.java_source_summaries.scan_tree",
        lambda _p: ([summary], {}, 1),
    )
    monkeypatch.setattr(
        "packages.semgrep.source_wrapper_rules.generate_rules_yaml",
        lambda _s: "rules: []\n",
    )
    monkeypatch.setattr(
        "packages.semgrep.runner.is_available", lambda: True,
    )
    monkeypatch.setattr(
        "packages.semgrep.runner.run_rule",
        lambda *a, **k: run_result,
    )


def test_errored_run_with_no_findings_retains_diagnostic_sarif(
    tmp_path, monkeypatch, capsys,
):
    """Zero findings retain explicit failure and mechanical wrapper names."""
    repo = tmp_path / "repo"
    repo.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    _wire_stage(
        monkeypatch, FakeSemgrepResult(errors=["rule parse error"]),
    )

    sarifs, wrappers = _scanner.run_source_wrapper_stage(repo, out_dir)
    assert sarifs == [str(out_dir / "source-wrappers.sarif")]
    assert wrappers == ["getTheParameter"]
    run = json.loads(Path(sarifs[0]).read_text())["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert "incomplete" in capsys.readouterr().err


def test_clean_zero_finding_run_still_writes_sarif(
    tmp_path, monkeypatch,
):
    """Pin the boundary: a run with neither errors nor findings is a
    genuinely clean projection — the artifact is honest and keeps
    being written."""
    repo = tmp_path / "repo"
    repo.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    _wire_stage(monkeypatch, FakeSemgrepResult())

    sarifs, wrappers = _scanner.run_source_wrapper_stage(repo, out_dir)
    assert sarifs == [str(out_dir / "source-wrappers.sarif")]
    assert (out_dir / "source-wrappers.sarif").exists()
    assert wrappers == ["getTheParameter"]


@pytest.mark.parametrize('damage', [
    {'errors': ['another file failed']},
    {'files_failed': [{'path': 'other.java', 'reason': 'parse error'}]},
    {'skipped_rules': ['incompatible']},
    {'returncode': 2},
])
def test_source_wrapper_partial_hits_retain_execution_diagnostics(tmp_path, monkeypatch, damage):
    from core.reporting.scan_coverage import scan_execution_status
    from core.sarif.parser import generate_scan_metrics
    from packages.semgrep.models import SemgrepFinding, SemgrepResult

    repo = tmp_path / 'repo'
    repo.mkdir()
    out = tmp_path / 'out'
    out.mkdir()
    _wire_stage(monkeypatch, SemgrepResult(
        findings=[SemgrepFinding('App.java', 1, rule_id='wrapper.xss')], **damage,
    ))
    paths, names = _scanner.run_source_wrapper_stage(repo, out)
    metrics = generate_scan_metrics(paths)
    assert metrics['total_findings'] == 1
    assert names == ['getTheParameter']
    assert scan_execution_status(metrics) == 'partial'


@pytest.mark.parametrize('failure', ['missing-tool', 'exception'])
def test_source_wrapper_failed_invocations_produce_diagnostic_report(tmp_path, monkeypatch, failure):
    from core.reporting.scan_coverage import scan_execution_status
    from core.sarif.parser import generate_scan_metrics

    repo = tmp_path / 'repo'
    repo.mkdir()
    out = tmp_path / 'out'
    out.mkdir()
    _wire_stage(monkeypatch, FakeSemgrepResult())
    if failure == 'missing-tool':
        monkeypatch.setattr('packages.semgrep.runner.is_available', lambda: False)
    else:
        def crash(*a, **kw):
            raise RuntimeError('tool unavailable')
        monkeypatch.setattr('packages.semgrep.runner.run_rule', crash)
    paths, _ = _scanner.run_source_wrapper_stage(repo, out)
    metrics = generate_scan_metrics(paths)
    assert metrics['total_findings'] == 0
    assert metrics['tool_execution_failures'] == {'raptor-source-wrappers': 1}
    assert scan_execution_status(metrics) == 'partial'



def test_source_wrapper_export_retains_direct_source_span(tmp_path, monkeypatch):
    from packages.semgrep.models import SemgrepFinding, SemgrepResult, parse_sarif

    repo = tmp_path / 'repo'
    repo.mkdir()
    out = tmp_path / 'out'
    out.mkdir()
    _wire_stage(monkeypatch, SemgrepResult(findings=[
        SemgrepFinding('App.java', 7, rule_id='wrapper.xss', column=2, line_end=8, column_end=11),
    ]))
    paths, _ = _scanner.run_source_wrapper_stage(repo, out)
    finding = parse_sarif(Path(paths[0]).read_text())[0]
    assert (finding.line, finding.column, finding.line_end, finding.column_end) == (7, 2, 8, 11)



def test_generated_export_does_not_invent_line_one_for_unknown_coordinates():
    from packages.semgrep.models import parse_sarif_data

    document = _scanner._stage_findings_to_sarif(
        [('wrapper', {'file': 'App.java', 'line': 0, 'message': 'unlocated finding'})],
        tool_name='raptor-source-wrappers', rule_prefix='source-wrapper',
    )
    region = document['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']
    assert region == {}
    assert parse_sarif_data(document)[0].line == 0


def test_generated_source_export_does_not_rebind_backwards_end_column():
    document = _scanner._stage_findings_to_sarif(
        [('wrapper', {'file': 'App.java', 'line': 8, 'line_end': 7,
                      'column': 9, 'column_end': 12, 'message': 'finding'})],
        tool_name='raptor-source-wrappers', rule_prefix='source-wrapper',
    )
    rows = document['runs'][0]['results']
    assert len(rows) == 1
    assert rows[0]['locations'][0]['physicalLocation']['region'] == {'startLine': 8, 'startColumn': 9}
