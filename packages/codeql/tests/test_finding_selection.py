"""Global CodeQL selection preserves signal, budgets, and owning SARIF runs."""

from __future__ import annotations

import copy
import itertools
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import raptor_codeql
from packages.codeql.agent import CodeQLWorkflowResult
from packages.codeql.autonomous_analyzer import (
    AutonomousAnalysisResult,
    AutonomousCodeQLAnalyzer,
    CodeQLFinding,
    VulnerabilityAnalysis,
)
from packages.codeql.finding_selection import select_findings_for_analysis


def _result(identity, level=None):
    result = {
        "ruleId": identity,
        "message": {"text": identity},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f"src/{identity}.py"},
        }}],
        "partialFingerprints": {"primaryLocationLineHash": identity},
    }
    if level is not None:
        result["level"] = level
    return result


def _run(*results, language="python", default=None, extension=False):
    rules = [{"id": result["ruleId"],
              "shortDescription": {"text": f"{language}:{result['ruleId']}"},
              **({"defaultConfiguration": {"level": default}} if default else {})}
             for result in results]
    tool = {"driver": {"name": "CodeQL", "rules": [] if extension else rules}}
    if extension:
        tool["extensions"] = [{"name": "curated", "rules": rules}]
    return {"tool": tool, "properties": {"language": language}, "results": list(results)}


def _write(tmp_path, name, *runs):
    path = tmp_path / name
    path.write_text(json.dumps({"version": "2.1.0", "runs": list(runs)}))
    return path


def test_later_language_and_query_pass_can_win_global_cap(tmp_path):
    early = _write(tmp_path, "python.sarif", _run(_result("early", "note")))
    later = _write(tmp_path, "java_curated.sarif",
                   _run(_result("strong", "error"), language="java"))
    selected, count = select_findings_for_analysis([early, later], 1)
    assert count == 2
    assert [candidate.result["ruleId"] for candidate in selected] == ["strong"]
    assert selected[0].sarif_file == later


def test_order_is_independent_of_file_run_and_result_enumeration(tmp_path):
    documents = {
        "python.sarif": [_run(_result("c", "warning"), _result("a", "warning")),
                         _run(_result("d", "warning"))],
        "java.sarif": [_run(_result("b", "warning"), language="java")],
        "curated.sarif": [_run(_result("e", "warning"), language="go")],
    }
    paths = [_write(tmp_path, name, *runs) for name, runs in documents.items()]
    baseline, _ = select_findings_for_analysis(paths, 3)
    expected = [candidate.result for candidate in baseline]
    for reverse_runs, reverse_results in itertools.product([False, True], repeat=2):
        for name, original in documents.items():
            runs = copy.deepcopy(original)
            if reverse_runs:
                runs.reverse()
            if reverse_results:
                for run in runs:
                    run["results"].reverse()
            _write(tmp_path, name, *runs)
        for order in itertools.permutations(paths):
            selected, count = select_findings_for_analysis(order, 3)
            assert count == 5
            assert [candidate.result for candidate in selected] == expected


def test_inherited_severity_uses_owning_run_without_mutating_result(tmp_path):
    # Equal rule IDs in different runs must not borrow each other's metadata.
    result = _result("shared")
    path = _write(tmp_path, "multi.sarif",
                  _run(result, language="python", default="warning"),
                  _run(result, language="java", default="error", extension=True))
    selected, count = select_findings_for_analysis([path], 1)
    assert count == 2
    candidate = selected[0]
    assert candidate.run["properties"]["language"] == "java"
    assert candidate.result is candidate.run["results"][0]
    assert "level" not in candidate.result
    assert json.loads(path.read_text())["runs"][0]["results"][0] == result


def test_explicit_level_overrides_rule_default(tmp_path):
    path = _write(tmp_path, "levels.sarif",
                  _run(_result("explicit-note", "note"), default="error"),
                  _run(_result("warning", "warning")))
    selected, _ = select_findings_for_analysis([path], 1)
    assert selected[0].result["ruleId"] == "warning"


def test_signal_policy_is_preserved_and_all_findings_are_ranked(tmp_path):
    proven = {**_result("exploitable", "note"), "is_exploitable": True}
    path = _write(tmp_path, "signals.sarif", _run(
        _result("note", "note"), _result("error", "error"), proven,
    ))
    selected, count = select_findings_for_analysis([path], 20)
    assert count == 3
    assert [candidate.result["ruleId"] for candidate in selected] == [
        "exploitable", "error", "note",
    ]


@pytest.mark.parametrize("cap", [0, -1])
def test_nonpositive_cap_selects_nothing(tmp_path, cap):
    path = _write(tmp_path, "empty-budget.sarif", _run(_result("candidate", "error")))
    selected, count = select_findings_for_analysis([path], cap)
    assert selected == []
    assert count == 1


def test_unreadable_empty_and_malformed_entries_do_not_hide_valid_runs(tmp_path):
    broken = tmp_path / "broken.sarif"
    broken.write_text("not json")
    empty = _write(tmp_path, "empty.sarif")
    valid = _write(tmp_path, "valid.sarif", None, {"results": None},
                   {"results": [None, _result("valid", "error")]})
    selected, count = select_findings_for_analysis(
        [tmp_path / "missing.sarif", broken, empty, valid], 5,
    )
    assert count == 1
    assert selected[0].result["ruleId"] == "valid"


@pytest.fixture
def workflow(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    scan = CodeQLWorkflowResult(
        success=True, repo_path=str(tmp_path), timestamp="test", duration_seconds=0,
        languages_detected={}, databases_created={}, analyses_completed={},
        total_findings=3, sarif_files=[], errors=[],
    )
    agent = Mock(spec=raptor_codeql.CodeQLAgent)
    agent.out_dir = out
    agent.run_autonomous_analysis.return_value = scan
    analyzer = Mock(spec=AutonomousCodeQLAnalyzer)

    def analyze(**kwargs):
        result = kwargs["sarif_result"]
        finding = CodeQLFinding(
            rule_id=result["ruleId"], rule_name=result["ruleId"],
            message=result["message"]["text"], level=result.get("level", "warning"),
            file_path=result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            start_line=0, end_line=0, snippet="",
        )
        assessment = VulnerabilityAnalysis(
            is_true_positive=False, is_exploitable=False, exploitability_score=0,
            severity_assessment="low", reasoning="test", attack_scenario="",
            prerequisites=[], impact="", cvss_estimate=0, mitigation="",
        )
        return AutonomousAnalysisResult(
            finding=finding, analysis=assessment, dataflow_validation=None,
            exploitable=False, exploit_code=None, exploit_compiled=False,
            validation_result=None, refinement_iterations=0, total_duration_seconds=0,
        )

    analyzer.analyze_finding_autonomous.side_effect = analyze
    client = Mock(short_circuits=0)
    get_client = Mock(return_value=client)
    monkeypatch.setattr(raptor_codeql, "CodeQLAgent", Mock(return_value=agent))
    monkeypatch.setattr(raptor_codeql, "AutonomousCodeQLAnalyzer", Mock(return_value=analyzer))
    monkeypatch.setattr(raptor_codeql, "get_llm_client", get_client)
    monkeypatch.setattr(raptor_codeql, "get_exploit_validator", Mock(return_value=None))
    monkeypatch.setattr(raptor_codeql, "get_multi_turn_analyzer", Mock(return_value=None))
    monkeypatch.setattr(raptor_codeql, "store_codeql_build_reliability", Mock())

    def run(paths, cap):
        scan.sarif_files = [str(path) for path in paths]
        scan.total_findings = sum(
            len(run.get("results", []))
            for path in paths for run in json.loads(path.read_text())["runs"]
        )
        args = SimpleNamespace(
            repo=str(tmp_path), out=str(out), codeql_cli=None, languages=None,
            build_command=None, force=False, extended=False, min_files=1,
            traced_build=False, scan_only=False, no_visualizations=True,
            max_findings=cap,
        )
        raptor_codeql.run_autonomous_workflow(args)
        return json.loads((out / "autonomous_summary.json").read_text())

    return run, analyzer.analyze_finding_autonomous, get_client


def test_workflow_analyzes_later_run_with_its_actual_metadata(tmp_path, workflow):
    run_workflow, analyze, _client = workflow
    early = _write(tmp_path, "early.sarif", _run(_result("weak", "note")))
    later = _write(tmp_path, "later.sarif", _run(_result("unused", "note")),
                   _run(_result("strong"), language="java", default="error"))
    summary = run_workflow([early, later], 1)
    analyze.assert_called_once()
    call = analyze.call_args.kwargs
    assert call["sarif_result"]["ruleId"] == "strong"
    assert call["sarif_run"]["properties"]["language"] == "java"
    assert call["sarif_result"] is call["sarif_run"]["results"][0]
    assert summary["analyzed"] == 1
    assert summary["analysis_selection"] == {
        "candidates": 3, "selected": 1, "deferred": 2, "attempted": 1, "failed": 0,
    }


def test_workflow_failures_do_not_expand_global_budget(tmp_path, workflow):
    run_workflow, analyze, _client = workflow
    paths = [_write(tmp_path, f"{level}.sarif", _run(_result(level, level)))
             for level in ["note", "warning", "error"]]
    analyze.side_effect = RuntimeError("analysis unavailable")
    summary = run_workflow(paths, 1)
    analyze.assert_called_once()
    assert analyze.call_args.kwargs["sarif_result"]["ruleId"] == "error"
    assert summary["analyzed"] == 0
    assert summary["analysis_selection"] == {
        "candidates": 3, "selected": 1, "deferred": 2, "attempted": 1, "failed": 1,
    }


def test_workflow_zero_budget_needs_no_llm(tmp_path, workflow):
    run_workflow, analyze, client = workflow
    path = _write(tmp_path, "findings.sarif", _run(_result("candidate", "error")))
    summary = run_workflow([path], 0)
    client.assert_not_called()
    analyze.assert_not_called()
    assert summary["analysis_selection"] == {
        "candidates": 1, "selected": 0, "deferred": 1, "attempted": 0, "failed": 0,
    }


@pytest.mark.parametrize("fields", [
    {"tree_class": []}, {"tree_class": {}},
    {"exploitability_score": 10**400},
    {"exploitability_score": "NaN"}, {"exploitability_score": "Infinity"},
])
def test_malformed_ranking_fields_do_not_abort_selection(tmp_path, fields):
    malformed = {**_result("malformed", "note"), **fields}
    path = _write(tmp_path, "hostile.sarif", _run(malformed, _result("valid", "error")))
    selected, count = select_findings_for_analysis([path], 1)
    assert count == 2
    assert selected[0].result["ruleId"] == "valid"


def test_same_file_and_symlink_do_not_spend_budget_twice(tmp_path):
    first = _write(tmp_path, "first.sarif", _run(_result("first", "error")))
    alias = tmp_path / "alias.sarif"
    alias.symlink_to(first)
    second = _write(tmp_path, "second.sarif", _run(_result("second", "warning")))
    selected, count = select_findings_for_analysis([first, alias, first, second], 2)
    assert count == 2
    assert [c.result["ruleId"] for c in selected] == ["first", "second"]


def test_extension_collision_uses_same_descriptor_for_selection_and_analysis(tmp_path):
    result = _result("shared")
    result["rule"] = {"id": "shared", "toolComponent": {"index": 0}}
    run = _run(result, default="note")
    run["tool"]["extensions"] = [{"name": "extension", "rules": [{
        "id": "shared", "name": "Extension rule",
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["external/cwe/cwe-078"]},
    }]}]
    path = _write(tmp_path, "collision.sarif", run, _run(_result("other", "warning")))
    selected, _ = select_findings_for_analysis([path], 1)
    candidate = selected[0]
    assert candidate.result["ruleId"] == "shared"
    analyzer = AutonomousCodeQLAnalyzer.__new__(AutonomousCodeQLAnalyzer)
    finding = analyzer.parse_sarif_finding(candidate.result, candidate.run)
    assert (finding.rule_name, finding.level, finding.cwe) == (
        "Extension rule", "error", "CWE-078",
    )


def test_malformed_rule_id_does_not_abort_workflow_logging(tmp_path, workflow):
    run_workflow, analyze, _client = workflow
    result = _result("malformed", "error")
    result["ruleId"] = {"invalid": "object"}
    path = _write(tmp_path, "malformed-id.sarif", {"results": [result]})
    analyze.side_effect = ValueError("invalid descriptor")
    summary = run_workflow([path], 1)
    analyze.assert_called_once()
    assert summary["analysis_selection"]["failed"] == 1
