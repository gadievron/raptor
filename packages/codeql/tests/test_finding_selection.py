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
    selected, count, _duplicates = select_findings_for_analysis([early, later], 1)
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
    baseline, _, _duplicates = select_findings_for_analysis(paths, 3)
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
            selected, count, _duplicates = select_findings_for_analysis(order, 3)
            assert count == 5
            assert [candidate.result for candidate in selected] == expected


def test_inherited_severity_uses_owning_run_without_mutating_result(tmp_path):
    # Equal rule IDs in different runs must not borrow each other's metadata.
    result = _result("shared")
    path = _write(tmp_path, "multi.sarif",
                  _run(result, language="python", default="warning"),
                  _run(result, language="java", default="error", extension=True))
    selected, count, _duplicates = select_findings_for_analysis([path], 1)
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
    selected, _, _duplicates = select_findings_for_analysis([path], 1)
    assert selected[0].result["ruleId"] == "warning"


def test_signal_policy_is_preserved_and_all_findings_are_ranked(tmp_path):
    proven = {**_result("exploitable", "note"), "is_exploitable": True}
    path = _write(tmp_path, "signals.sarif", _run(
        _result("note", "note"), _result("error", "error"), proven,
    ))
    selected, count, _duplicates = select_findings_for_analysis([path], 20)
    assert count == 3
    assert [candidate.result["ruleId"] for candidate in selected] == [
        "exploitable", "error", "note",
    ]


@pytest.mark.parametrize("cap", [0, -1])
def test_nonpositive_cap_selects_nothing(tmp_path, cap):
    path = _write(tmp_path, "empty-budget.sarif", _run(_result("candidate", "error")))
    selected, count, _duplicates = select_findings_for_analysis([path], cap)
    assert selected == []
    assert count == 1


def test_unreadable_empty_and_malformed_entries_do_not_hide_valid_runs(tmp_path):
    broken = tmp_path / "broken.sarif"
    broken.write_text("not json")
    empty = _write(tmp_path, "empty.sarif")
    valid = _write(tmp_path, "valid.sarif", None, {"results": None},
                   {"results": [None, _result("valid", "error")]})
    selected, count, _duplicates = select_findings_for_analysis(
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
        "candidates": 3, "unique": 3, "duplicates": 0, "selected": 1, "deferred": 2, "attempted": 1, "failed": 0,
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
        "candidates": 3, "unique": 3, "duplicates": 0, "selected": 1, "deferred": 2, "attempted": 1, "failed": 1,
    }


def test_workflow_zero_budget_needs_no_llm(tmp_path, workflow):
    run_workflow, analyze, client = workflow
    path = _write(tmp_path, "findings.sarif", _run(_result("candidate", "error")))
    summary = run_workflow([path], 0)
    client.assert_not_called()
    analyze.assert_not_called()
    assert summary["analysis_selection"] == {
        "candidates": 1, "unique": 1, "duplicates": 0, "selected": 0, "deferred": 1, "attempted": 0, "failed": 0,
    }


@pytest.mark.parametrize("fields", [
    {"tree_class": []}, {"tree_class": {}},
    {"exploitability_score": 10**400},
    {"exploitability_score": "NaN"}, {"exploitability_score": "Infinity"},
])
def test_malformed_ranking_fields_do_not_abort_selection(tmp_path, fields):
    malformed = {**_result("malformed", "note"), **fields}
    path = _write(tmp_path, "hostile.sarif", _run(malformed, _result("valid", "error")))
    selected, count, _duplicates = select_findings_for_analysis([path], 1)
    assert count == 2
    assert selected[0].result["ruleId"] == "valid"


def test_same_file_and_symlink_do_not_spend_budget_twice(tmp_path):
    first = _write(tmp_path, "first.sarif", _run(_result("first", "error")))
    alias = tmp_path / "alias.sarif"
    alias.symlink_to(first)
    second = _write(tmp_path, "second.sarif", _run(_result("second", "warning")))
    selected, count, _duplicates = select_findings_for_analysis([first, alias, first, second], 2)
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
    selected, _, _duplicates = select_findings_for_analysis([path], 1)
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


def _located_result(identity="shared", level=None):
    """Coordinates describe this synthetic fixture, never repository lines."""
    result = _result(identity, level)
    result["locations"][0]["physicalLocation"]["region"] = {
        "startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 5,
    }
    return result


def test_duplicates_do_not_crowd_distinct_bug_out_of_cap(tmp_path):
    paths = [
        _write(tmp_path, "default.sarif", _run(_located_result(level="error"))),
        _write(tmp_path, "curated.sarif", _run(_located_result(level="error"))),
        _write(tmp_path, "other.sarif", _run(_located_result("other", "warning"))),
    ]
    for order in itertools.permutations(paths):
        selected, count, duplicates = select_findings_for_analysis(order, 2)
        assert (count, duplicates) == (3, 1)
        assert [c.result["ruleId"] for c in selected] == ["shared", "other"]


@pytest.mark.parametrize("inherited", [False, True])
def test_duplicate_keeps_strongest_report_and_original_run(tmp_path, inherited):
    weak = _located_result(level=None if inherited else "note")
    strong = _located_result(level=None if inherited else "error")
    weak_path = _write(tmp_path, "weak.sarif", _run(weak, default="note"))
    strong_path = _write(tmp_path, "strong.sarif", _run(strong, default="error"))
    for paths in ([weak_path, strong_path], [strong_path, weak_path]):
        selected, count, duplicates = select_findings_for_analysis(paths, 5)
        assert (count, duplicates, len(selected)) == (2, 1, 1)
        assert selected[0].sarif_file == strong_path
        assert selected[0].result is selected[0].run["results"][0]
        assert selected[0].result == strong


@pytest.mark.parametrize("difference", [
    "rule", "message", "column", "end_column", "end_line", "flow",
    "fingerprint", "secondary_location", "property", "suppression",
    "component", "driver", "base_uri", "artifacts",
])
def test_similar_findings_with_distinct_evidence_stay_separate(tmp_path, difference):
    first = _run(_located_result())
    second = copy.deepcopy(first)
    result = second["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    if difference == "rule":
        result["ruleId"] = "different"
        second["tool"]["driver"]["rules"][0]["id"] = "different"
    elif difference == "message":
        result["message"]["text"] = "different evidence"
    elif difference == "column":
        physical["region"]["startColumn"] += 1
    elif difference == "end_column":
        physical["region"]["endColumn"] += 1
    elif difference == "end_line":
        physical["region"]["endLine"] += 1
    elif difference == "flow":
        result["codeFlows"] = [{"threadFlows": [{"locations": [{
            "location": {"physicalLocation": {
                "artifactLocation": {"uri": "src/source.py"},
                "region": {"startLine": 1},
            }},
        }]}]}]
    elif difference == "fingerprint":
        result["partialFingerprints"]["primaryLocationLineHash"] = "different"
    elif difference == "secondary_location":
        result["relatedLocations"] = [{"id": 1, "message": {"text": "source"}}]
    elif difference == "property":
        result["properties"] = {"source_kind": "additional-source"}
    elif difference == "suppression":
        result["suppressions"] = [{"kind": "external"}]
    elif difference == "component":
        rule = second["tool"]["driver"]["rules"].pop()
        second["tool"]["extensions"] = [{"name": "other-pack", "rules": [rule]}]
        result["rule"] = {"id": "shared", "toolComponent": {"index": 0}}
    elif difference == "driver":
        second["tool"]["driver"]["name"] = "different tool"
    elif difference == "base_uri":
        second["originalUriBaseIds"] = {"SRCROOT": {"uri": "file:///different/"}}
    elif difference == "artifacts":
        second["artifacts"] = [{"location": {"uri": "different.py"}}]
    path = _write(tmp_path, "distinct.sarif", first, second)
    selected, count, duplicates = select_findings_for_analysis([path], 5)
    assert (len(selected), count, duplicates) == (2, 2, 0)


@pytest.mark.parametrize("missing", ["rule", "location", "region", "message", "tool"])
def test_incomplete_metadata_is_not_enough_to_merge(tmp_path, missing):
    run = _run(_located_result())
    if missing == "rule":
        run["tool"]["driver"]["rules"] = []
    elif missing == "location":
        run["results"][0]["locations"] = []
    elif missing == "region":
        del run["results"][0]["locations"][0]["physicalLocation"]["region"]
    elif missing == "message":
        run["results"][0]["message"] = {}
    else:
        run["tool"] = None
    path = _write(tmp_path, "incomplete.sarif", run, copy.deepcopy(run))
    selected, count, duplicates = select_findings_for_analysis([path], 5)
    assert (len(selected), count, duplicates) == (2, 2, 0)


def test_run_local_rule_indexes_do_not_prevent_matching_reports(tmp_path):
    first = _run(_located_result())
    second = copy.deepcopy(first)
    first["results"][0]["ruleIndex"] = 0
    second["tool"]["driver"]["rules"].insert(0, {"id": "unrelated"})
    second["results"][0]["ruleIndex"] = 1
    path = _write(tmp_path, "indexes.sarif", first, second)
    selected, count, duplicates = select_findings_for_analysis([path], 5)
    assert (len(selected), count, duplicates) == (1, 2, 1)


@pytest.mark.parametrize("cap", [0, -1, 1])
def test_duplicate_counts_remain_accurate_at_small_budgets(tmp_path, cap):
    run = _run(_located_result())
    path = _write(tmp_path, "counts.sarif", run, copy.deepcopy(run))
    selected, count, duplicates = select_findings_for_analysis([path], cap)
    assert (len(selected), count, duplicates) == (max(0, cap), 2, 1)


def test_workflow_counts_duplicates_separately_from_deferred_bugs(tmp_path, workflow):
    run_workflow, analyze, _client = workflow
    paths = [
        _write(tmp_path, "default.sarif", _run(_located_result(level="error"))),
        _write(tmp_path, "curated.sarif", _run(_located_result(level="error"))),
        _write(tmp_path, "other.sarif", _run(_located_result("other", "warning"))),
    ]
    summary = run_workflow(paths, 2)
    assert analyze.call_count == 2
    assert summary["analysis_selection"] == {
        "candidates": 3, "duplicates": 1, "unique": 2,
        "selected": 2, "deferred": 0, "attempted": 2, "failed": 0,
    }


def test_many_duplicates_and_failed_attempt_still_obey_cap(tmp_path, workflow):
    run_workflow, analyze, _client = workflow
    path = _write(tmp_path, "many.sarif",
                  *[_run(_located_result(level="error")) for _ in range(20)],
                  _run(_located_result("other", "warning")))
    analyze.side_effect = RuntimeError("model unavailable")
    summary = run_workflow([path], 1)
    analyze.assert_called_once()
    assert summary["analysis_selection"] == {
        "candidates": 21, "duplicates": 19, "unique": 2,
        "selected": 1, "deferred": 1, "attempted": 1, "failed": 1,
    }


def test_extension_descriptor_indexes_and_file_order_do_not_affect_dedup(tmp_path):
    first = _run(_located_result(), extension=True)
    second = copy.deepcopy(first)
    first["results"][0]["rule"] = {"index": 0, "toolComponent": {"index": 0}}
    second["tool"]["extensions"].insert(0, {"name": "unrelated", "rules": []})
    second["results"][0]["rule"] = {"index": 0, "toolComponent": {"index": 1}}
    a = _write(tmp_path, "a.sarif", first)
    b = _write(tmp_path, "b.sarif", second)
    selected, count, duplicates = select_findings_for_analysis([a, b], 5)
    reverse, _, _ = select_findings_for_analysis([b, a], 5)
    assert (len(selected), count, duplicates) == (1, 2, 1)
    assert selected == reverse
    assert json.loads(a.read_text())["runs"][0] == first
    assert json.loads(b.read_text())["runs"][0] == second


@pytest.mark.parametrize("context", [
    "graphs", "threadFlowLocations", "webRequests", "webResponses",
    "externalPropertyFileReferences", "versionControlProvenance", "invocations",
])
def test_referenced_run_context_cannot_be_ignored(tmp_path, context):
    first = _run(_located_result())
    second = copy.deepcopy(first)
    if context == "invocations":
        first[context] = [{"workingDirectory": {"uri": "file:///first/"}}]
        second[context] = [{"workingDirectory": {"uri": "file:///second/"}}]
    else:
        first[context] = [{"identity": "first"}]
        second[context] = [{"identity": "second"}]
    path = _write(tmp_path, "contexts.sarif", first, second)
    selected, count, duplicates = select_findings_for_analysis([path], 5)
    assert (len(selected), count, duplicates) == (2, 2, 0)


def _batch_selection_reference(paths, cap):
    """Full-materialization oracle for the original selection algorithm."""
    from core.orchestration.skill_dispatch import rank_findings_by_signal
    from core.sarif.parser import get_result_rule, load_sarif, rule_default_level
    from packages.codeql.finding_selection import _content_key, _duplicate_key, all_run_results

    records = []
    for path in sorted({path.resolve() for path in paths}):
        document = load_sarif(path)
        if not document:
            continue
        contexts = {}
        for run, result in all_run_results(document):
            rule = get_result_rule(run, result)
            tool = run.get("tool", {})
            components = [tool.get("driver", {}), *tool.get("extensions", [])]
            owner = next((c for c in components if isinstance(c, dict)
                          and any(r is rule for r in c.get("rules", []))), None)
            signal = dict(result)
            if signal.get("level") is None:
                signal["level"] = rule_default_level(rule) or "warning"
            records.append((
                (_content_key(result), _content_key({k: v for k, v in run.items() if k != "results"}), str(path)),
                signal, (path, run, result), _duplicate_key(run, result, rule, owner, contexts),
            ))
    records.sort(key=lambda row: row[0])
    by_signal = {id(row[1]): row for row in records}
    seen = set()
    unique = []
    for signal in rank_findings_by_signal([row[1] for row in records]):
        row = by_signal[id(signal)]
        key = row[3]
        if key is not None:
            if key in seen:
                continue
            seen.add(key)
        unique.append(row[2])
    return unique[:max(0, cap)], len(records), len(records) - len(unique)


def _selection_signature(candidates):
    return [(str(path), result, {key: value for key, value in run.items() if key != "results"})
            for path, run, result in candidates]


@pytest.mark.parametrize("seed", range(8))
@pytest.mark.parametrize("cap", [0, 1, 3, 20, 100])
def test_bounded_selection_matches_batch_oracle(tmp_path, seed, cap):
    import random

    randomizer = random.Random(seed)
    pool = [_located_result(f"rule-{i}") for i in range(12)]
    paths = []
    for file_index in range(3):
        runs = []
        for _ in range(2):
            results = [copy.deepcopy(randomizer.choice(pool)) for _ in range(16)]
            for result in results:
                result["level"] = randomizer.choice(["error", "warning", "note", None])
                result["exploitability_score"] = randomizer.choice([0, 0.2, 1, "bad", 10**400])
                result["is_exploitable"] = randomizer.choice([True, False, None])
                result["tree_class"] = randomizer.choice(["test", "production", [], {}])
                if randomizer.randrange(5) == 0:
                    result["codeFlows"] = [{"message": {"text": str(randomizer.randrange(3))}}]
            run = _run(*results, default=randomizer.choice(["error", "warning", "note"]))
            # SARIF rule tables contain one descriptor per ID, even when
            # many results reference it.
            rules = run["tool"]["driver"]["rules"]
            run["tool"]["driver"]["rules"] = list({r["id"]: r for r in rules}.values())
            runs.append(run)
        paths.append(_write(tmp_path, f"pass-{file_index}.sarif", *runs))
    expected, count, duplicates = _batch_selection_reference(paths, cap)
    randomizer.shuffle(paths)
    actual, actual_count, actual_duplicates = select_findings_for_analysis(paths, cap)
    assert (actual_count, actual_duplicates) == (count, duplicates)
    assert _selection_signature([(c.sarif_file, c.run, c.result) for c in actual]) == _selection_signature(expected)
    retained_runs = {id(c.run): c.run for c in actual}
    assert sum(len(run["results"]) for run in retained_runs.values()) == len(actual)


def test_evicted_duplicate_group_can_return_with_stronger_report(tmp_path):
    paths = [
        _write(tmp_path, "weak.sarif", _run(_located_result(level="note"))),
        _write(tmp_path, "other.sarif", _run(_located_result("other", "warning"))),
        _write(tmp_path, "strong.sarif", _run(_located_result(level="error"))),
    ]
    expected, count, duplicates = _batch_selection_reference(paths, 1)
    actual, actual_count, actual_duplicates = select_findings_for_analysis(paths, 1)
    assert (actual_count, actual_duplicates) == (count, duplicates) == (3, 1)
    assert actual[0].sarif_file == paths[-1]
    assert _selection_signature([(c.sarif_file, c.run, c.result) for c in actual]) == _selection_signature(expected)


def test_retained_run_drops_sibling_payloads_but_parses_identically(tmp_path):
    results = [_located_result("strong", "error"), *[
        _located_result(f"weak-{i}", "note") for i in range(100)
    ]]
    run = _run(*results, default="warning")
    path = _write(tmp_path, "siblings.sarif", run)
    before = path.read_bytes()
    selected, count, duplicates = select_findings_for_analysis([path], 1)
    assert (count, duplicates) == (101, 0)
    assert selected[0].run["results"] == [results[0]]
    analyzer = AutonomousCodeQLAnalyzer.__new__(AutonomousCodeQLAnalyzer)
    assert analyzer.parse_sarif_finding(selected[0].result, selected[0].run) == analyzer.parse_sarif_finding(results[0], run)
    assert path.read_bytes() == before


def test_finished_documents_and_unselected_payloads_are_released(tmp_path, monkeypatch):
    import gc
    import weakref

    import packages.codeql.finding_selection as selection

    class TrackedDict(dict):
        pass

    paths = [_write(tmp_path, f"pass-{i}.sarif", _run(
        _located_result(f"strong-{i}", "error"), _located_result(f"weak-{i}", "note"),
    )) for i in range(3)]
    original_loader = selection.load_sarif
    previous = []

    def load(path):
        # These acyclic fixture objects need no scan of the worker's old
        # generations; full collections scale with unrelated suite state.
        gc.collect(0)
        assert all(ref() is None for ref in previous)
        document = original_loader(path)
        run = TrackedDict(document["runs"][0])
        skipped = TrackedDict(run["results"][-1])
        run["results"][-1] = skipped
        document["runs"][0] = run
        previous[:] = [weakref.ref(run), weakref.ref(skipped)]
        return document

    monkeypatch.setattr(selection, "load_sarif", load)
    selected, count, duplicates = selection.select_findings_for_analysis(paths, 1)
    gc.collect(0)
    assert all(ref() is None for ref in previous)
    assert (len(selected), count, duplicates) == (1, 6, 0)
