"""Skipped rules cannot contribute replay coverage."""

import json

import pytest

from packages.checker_synthesis import replay_sweep as rs
from packages.checker_synthesis.tests.test_replay_sweep import (
    _manifest_entry,
    _semgrep_result,
    _write_library,
)
from packages.semgrep.models import parse_json_output


@pytest.mark.parametrize("findings", [0, 2])
def test_skipped_rule_retains_findings_without_coverage(tmp_path, monkeypatch, findings):
    lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
    manifest = lib_dir / "manifest.json"
    before = manifest.read_bytes()
    target = tmp_path / "target"
    target.mkdir()
    metadata = parse_json_output(json.dumps({
        "errors": [{
            "type": ["IncompatibleRule", {"rule_id": "sg"}],
            "level": "info", "rule_id": "sg",
            "message": "Rule requires Semgrep >= 999.0.0",
            "path": "rules.yml",
        }],
    }))
    result = _semgrep_result(findings, rule_id="sg")
    result.errors = metadata["errors"]
    result.skipped_rules = metadata["skipped_rules"]
    assert result.ok and result.skipped_rules
    calls = []

    def run_rule(*args, **kwargs):
        calls.append((args, kwargs))
        return result

    monkeypatch.setattr(rs.semgrep_runner, "run_rule", run_rule)
    report = rs.run_sweep([target], library_dir=lib_dir, record=True)
    assert len(calls) == 1
    assert report.recorded_updates == 0
    assert manifest.read_bytes() == before
    assert len(report.matches) == findings
    assert report.partial == ([f"sg@{target}"] if findings else [])
    assert len(report.errors) == 1
    assert "999.0.0" in report.errors[0]
    assert result.errors == [] and result.ok


def test_error_level_skip_notice_is_reported_once(tmp_path, monkeypatch):
    result = _semgrep_result(0)
    result.errors = ["incompatible rule"]
    result.skipped_rules = ["incompatible rule"]
    monkeypatch.setattr(rs.semgrep_runner, "run_rule", lambda *a, **k: result)
    report = rs.SweepReport()
    matches, errored = rs._sweep_semgrep_rule(
        report, tmp_path, tmp_path / "rule.yml", rule_id="sg", cwe="CWE-20",
        provenance="rule-library", tier="library", tp_rate=None, targets_tested=0,
    )
    assert errored and matches == []
    assert report.errors == [f"semgrep sg @ {tmp_path}: incompatible rule"]
    assert result.errors == ["incompatible rule"]
