"""Tests for the source-wrapper projection /scan stage.

Same hyphenated-package importlib pattern as the other scanner tests.
The semgrep runner and the summary scanner are faked throughout — no
semgrep binary or tree-sitter required.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

# parents[3]: tests/ → static-analysis/ → packages/ → repo root
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
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


def test_errored_run_with_no_findings_refuses_clean_sarif(
    tmp_path, monkeypatch, capsys,
):
    """All-failed-looks-clean sibling shape: a semgrep run that
    errored without findings must not leave a zero-finding
    source-wrappers.sarif on disk (indistinguishable from a clean
    run for the SARIF merge and later readers)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    _wire_stage(
        monkeypatch, FakeSemgrepResult(errors=["rule parse error"]),
    )

    sarifs, wrappers = _scanner.run_source_wrapper_stage(repo, out_dir)
    assert sarifs == []
    assert wrappers == []
    assert not (out_dir / "source-wrappers.sarif").exists()
    err = capsys.readouterr().err
    assert "FAILED" in err
    assert "no SARIF" in err


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
