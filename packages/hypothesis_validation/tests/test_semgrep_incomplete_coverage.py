"""Incomplete Semgrep scans remain observations, not quiet refutations."""
import json
from pathlib import Path

from core.testing.module_bindings import patch_module_attribute
from packages.hypothesis_validation.adapters import semgrep as adapter_module
from packages.hypothesis_validation.verdict import verdict_from
from packages.hypothesis_validation.hypothesis import Hypothesis
from packages.hypothesis_validation.runner import validate
from packages.hypothesis_validation.tests.test_runner import FakeLLM
from packages.semgrep.models import SemgrepFinding, SemgrepResult, parse_json_output


def test_incomplete_semgrep_scan_preserves_matches_without_verdict(tmp_path, monkeypatch):
    target = tmp_path / "owned.py"
    target.write_text("value = 1\n", encoding="utf-8")
    adapter = adapter_module.SemgrepAdapter(sandbox=False)
    monkeypatch.setattr(adapter, "is_available", lambda: True)
    metadata = parse_json_output(json.dumps({"errors": [{
        "level": "warn", "type": "PartialParsing", "path": str(target),
        "message": "owned partial parse",
    }]}))
    assert metadata["errors"] == []
    assert len(metadata["files_failed"]) == 1
    incompatible = parse_json_output(json.dumps({"errors": [{
        "level": "info", "type": "IncompatibleRule", "path": "owned.yaml",
        "message": "owned incompatible rule",
    }]}))
    assert incompatible["errors"] == incompatible["files_failed"] == []
    assert len(incompatible["skipped_rules"]) == 1
    excluded = parse_json_output(json.dumps({"paths": {"skipped": [{
        "path": "excluded.py", "reason": "exclude_flags_match",
    }]}}))
    assert excluded["errors"] == excluded["files_failed"] == []
    assert excluded["skipped_summary"]["total"] == 1
    states = [(metadata["files_failed"], []), ([], incompatible["skipped_rules"]), ([], [])]
    for failed, skipped in states:
        for findings in ([], [SemgrepFinding(file=str(target), line=1, rule_id="owned", message="owned")]):
            result = SemgrepResult(returncode=0, findings=findings, files_failed=failed,
                                   skipped_rules=skipped, errors=metadata["errors"],
                                   skipped_summary=excluded["skipped_summary"])
            assert result.ok
            calls = []

            def run_rule(**kwargs):
                calls.append(kwargs)
                assert kwargs["target"] == target
                assert Path(kwargs["config"]).read_text() == "rules: []"
                return result

            patch_module_attribute(monkeypatch, adapter_module, "semgrep_pkg", "run_rule", run_rule)
            evidence = adapter.run("rules: []", target, env={})
            assert len(calls) == 1
            expected_matches = [finding.to_dict() for finding in findings]
            assert evidence.matches == expected_matches
            client = FakeLLM([
                {"tool": "semgrep", "rule": "rules: []"},
                {"verdict": "confirmed", "reasoning": "owned explanation"},
            ])
            validation = validate(Hypothesis(claim="owned claim", target=target),
                                  [adapter], client, env={})
            assert len(calls) == 2 and len(client.calls) == 2
            assert validation.evidence[0].matches == expected_matches
            assert validation.evidence[0].error == evidence.error
            assert validation.verdict == (
                "inconclusive" if failed or skipped else "confirmed" if findings else "refuted"
            )
            if failed or skipped:
                assert not evidence.success
                assert "incomplete Semgrep analysis" in evidence.error
                assert str(target) not in evidence.error
                assert verdict_from(evidence, "confirmed") == "inconclusive"
                assert verdict_from(evidence, "refuted") == "inconclusive"
            else:
                assert evidence.success
                assert verdict_from(evidence, "confirmed") == ("confirmed" if findings else "refuted")
