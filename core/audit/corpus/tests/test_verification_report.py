"""Saved evidence availability cannot change scores or masquerade as proof."""

from copy import deepcopy
from dataclasses import asdict
import json

import pytest

from core.audit.check_trace import _summarize_observations
from core.audit.corpus.corpus_metrics import compute_metrics
from core.audit.corpus import verification_report as report


def _snapshot(matching=(), other=()):
    def summary(outcomes):
        return _summarize_observations([
            {"scope": {}, "tool": "fixture", "outcome": outcome, "result": {"complete": True}}
            for outcome in outcomes
        ])
    return {"status": "recorded", "observations": {"matching_final_claim": summary(matching),
                                                   "other_claims": summary(other)}}


def _row(expected="finding", actual="suspicious", **extra):
    return {"function_id": "a.c:f", "bug_class": "auth", "expected": expected, "actual": actual,
            "mode": "security", "model": "fixture-model", **extra}


def test_availability_partition_preserves_scores_and_conflicting_outcomes():
    rows = [
        _row(verification=_snapshot(("confirmed", "refuted"))),
        _row("clean", verification=_snapshot(other=("confirmed",))),
        _row(actual="clean"),
        _row("clean", "clean", verification={"status": "unavailable"}),
        _row(actual="error", verification={"status": "recorded", "observations": {}}),
    ]
    original = deepcopy(rows)
    aggregate, _, _ = compute_metrics(rows)
    cohort = report.build_run_report(rows)["cohorts"][0]
    assert cohort["metrics"]["matrix"] == asdict(aggregate)
    assert cohort["metrics"]["precision"] == aggregate.precision
    assert cohort["metrics"]["recall"] == aggregate.recall
    assert sum(sum(v.values()) for v in cohort["availability_by_cell"].values()) == len(rows)
    for cell, state in [("tp", "matching"), ("fp", "other_claims_only"), ("fn", "missing"),
                        ("tn", "unavailable"), ("error", "malformed")]:
        assert cohort["availability_by_cell"][cell][state] == 1
    observed = cohort["matching_observations"]["tp"]
    assert observed["records"] == 2
    assert observed["rows_with_outcome"] == {"confirmed": 1, "refuted": 1}
    assert observed["by_tool"] == {"fixture": {"confirmed": 1, "refuted": 1}}
    assert cohort["matching_observations"]["fp"]["records"] == 0
    assert rows == original


def test_models_modes_profiles_and_kinds_do_not_mix():
    rows = [_row(), _row(model="other-model"), _row(mode="quality"),
            _row(profile="deployed"), _row(label_kind="synthetic_mutant")]
    result = report.build_run_report(rows, {"profile": "cold", "label_kind": "real"})
    assert len(result["cohorts"]) == 5
    assert all(c["rows"] == 1 for c in result["cohorts"])
    assert {c["context"]["label_kind"] for c in result["cohorts"]} == {"real", "synthetic_mutant"}
    unknown = report.build_run_report([_row()])["cohorts"][0]["context"]
    assert unknown["profile"] == unknown["label_kind"] == "unknown"


def test_raw_truth_and_explicit_mode_expectations_remain_separate():
    row = _row(evidence_tool="smt:check-fixture", expected_mode_results={"security": "clean"})
    cohort = report.build_run_report([row])["cohorts"][0]
    assert cohort["metrics"]["matrix"]["tp"] == 1
    assert cohort["availability_by_cell"]["tp"]["missing"] == 1
    assert cohort["mode_expectations"] == {"checked": 1, "mismatches": 1, "details": [{
        "function_id": "a.c:f", "mode": "security", "expected": "clean", "actual": "suspicious",
    }]}
    assert cohort["by_class"]["auth"]["metrics"] == cohort["metrics"]


def test_mode_details_preserve_secondary_actuals_and_skip_unexercised_or_error_rows():
    rows = [
        _row(mode="quality", actual="finding", security_actual="dark",
             expected_mode_results={"quality": "finding", "security": "clean", "unused": "finding"}),
        _row(function_id="b.c:g", mode="quality", actual="clean", security_actual="suspicious",
             expected_mode_results={"quality": "finding", "security": "clean"}),
        _row(actual="error", expected_mode_results={"security": "finding"}),
    ]
    original = deepcopy(rows)
    cohorts = report.build_run_report(rows)["cohorts"]
    quality = next(c for c in cohorts if c["context"]["mode"] == "quality")
    assert quality["mode_expectations"] == {"checked": 4, "mismatches": 2, "details": [
        {"function_id": "b.c:g", "mode": "quality", "expected": "finding", "actual": "clean"},
        {"function_id": "b.c:g", "mode": "security", "expected": "clean", "actual": "suspicious"},
    ]}
    assert quality["by_class"]["auth"]["mode_expectations"] == quality["mode_expectations"]
    error = next(c for c in cohorts if c["context"]["mode"] == "security")
    assert error["mode_expectations"] == {"checked": 0, "mismatches": 0, "details": []}
    assert rows == original


def test_label_support_counts_unreviewed_truth_without_changing_recall():
    rows = [
        _row(expected_mode_results={"security": "clean"}),
        _row(actual="error", expected_mode_results={"security": "finding"}),
        _row("clean", "clean"),
    ]
    cohort = report.build_run_report(rows)["cohorts"][0]
    assert cohort["label_support"] == {
        "raw": {"positive": 2, "negative": 1},
        "unreviewed": {"positive": 1, "negative": 0},
        "explicit_current_mode": {"positive": 1, "negative": 1, "unspecified": 1},
        "limits": [],
    }
    assert cohort["metrics"]["recall"] == 1.0
    assert cohort["metrics"]["matrix"]["error"] == 1


def test_single_polarity_classes_expose_measurement_limits():
    rows = [_row("clean", "suspicious", bug_class="lifecycle"),
            _row(bug_class="consistency", expected_mode_results={"security": "clean"})]
    classes = report.build_run_report(rows)["cohorts"][0]["by_class"]
    lifecycle = classes["lifecycle"]
    assert lifecycle["label_support"]["raw"] == {"positive": 0, "negative": 1}
    assert lifecycle["label_support"]["limits"] == ["no_positive_labels"]
    assert lifecycle["metrics"]["recall"] is None
    assert lifecycle["metrics"]["f1"] is None
    consistency = classes["consistency"]
    assert consistency["label_support"]["limits"] == ["no_negative_labels"]
    assert consistency["label_support"]["explicit_current_mode"] == {"positive": 0, "negative": 1, "unspecified": 0}
    assert consistency["metrics"]["precision"] == 1.0


def test_file_mode_metadata_does_not_invent_explicit_row_expectations():
    row = _row(expected_mode_results={"security": "finding"})
    row.pop("mode")
    cohort = report.build_run_report([row], {"mode": "security"})["cohorts"][0]
    assert cohort["context"]["mode"] == "security"
    assert cohort["label_support"]["explicit_current_mode"] == {"positive": 0, "negative": 0, "unspecified": 1}


def test_resources_are_recorded_at_run_level_without_estimating_missing_totals():
    result = report.build_run_report([_row(), _row(model="other")], {
        "total_spend_usd": 4.5, "wall_s": 120, "llm_s": 40, "cost_usd": 1.2,
    })
    assert result["recorded_run_resources"] == {"total_spend_usd": 4.5, "wall_s": 120, "llm_s": 40}
    assert all("recorded_run_resources" not in c for c in result["cohorts"])
    assert report.build_run_report([], {"cost_usd": 1.2})["recorded_run_resources"]["total_spend_usd"] is None
    invalid = report.build_run_report([], {"total_spend_usd": float("nan"), "wall_s": True, "llm_s": -1})
    assert all(v is None for v in invalid["recorded_run_resources"].values())


@pytest.mark.parametrize("bad", [True, -1, 1.5, float("nan")])
def test_invalid_snapshot_counts_are_unknown_without_changing_verdict_metrics(bad):
    snapshot = _snapshot(("confirmed",))
    snapshot["observations"]["matching_final_claim"]["records"] = bad
    cohort = report.build_run_report([_row(verification=snapshot)])["cohorts"][0]
    assert cohort["availability_by_cell"]["tp"]["malformed"] == 1
    assert cohort["metrics"]["matrix"]["tp"] == 1
    assert cohort["matching_observations"]["tp"]["records"] == 0


def test_inconsistent_tool_totals_are_not_credited():
    snapshot = _snapshot(("confirmed",))
    snapshot["observations"]["matching_final_claim"]["by_tool"]["fixture"]["confirmed"] = 99
    cohort = report.build_run_report([_row(verification=snapshot)])["cohorts"][0]
    assert cohort["availability_by_cell"]["tp"]["malformed"] == 1


def test_cli_compares_saved_files_without_following_artifact_references(tmp_path, capsys):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    output = tmp_path / "comparison.json"
    before.write_text(json.dumps([_row("clean")]))
    snapshot = _snapshot(("inconclusive",))
    snapshot["audit_dir"] = str(tmp_path / "does-not-exist")
    after.write_text(json.dumps({"meta": {"profile": "cold", "label_kind": "real",
                                        "model": "fixture-model", "model_resolved": "fixture/resolved"},
                                 "results": [_row("clean", verification=snapshot)]}))
    before_bytes, after_bytes = before.read_bytes(), after.read_bytes()
    assert report.main([str(before), str(after), "--output", str(output)]) == 0
    runs = json.loads(output.read_text())["runs"]
    assert len(runs) == 2
    assert runs[0]["cohorts"][0]["availability_by_cell"]["fp"]["missing"] == 1
    assert runs[1]["cohorts"][0]["availability_by_cell"]["fp"]["matching"] == 1
    assert runs[1]["cohorts"][0]["context"]["model"] == "fixture/resolved"
    assert "missing snapshots are unknown" in capsys.readouterr().out
    assert before.read_bytes() == before_bytes and after.read_bytes() == after_bytes


def test_cli_refuses_to_overwrite_input(tmp_path):
    source = tmp_path / "results.json"
    source.write_text(json.dumps([_row()]))
    original = source.read_bytes()
    with pytest.raises(SystemExit) as caught:
        report.main([str(source), "--output", str(source)])
    assert caught.value.code == 2
    assert source.read_bytes() == original


@pytest.mark.parametrize("failure", ["missing", "invalid_row", "oversized"])
def test_cli_rejects_invalid_inputs_without_writing_a_report(tmp_path, monkeypatch, failure):
    source = tmp_path / "results.json"
    output = tmp_path / "report.json"
    if failure != "missing":
        source.write_text(json.dumps([{}] if failure == "invalid_row" else [_row()]))
    if failure == "oversized":
        monkeypatch.setattr(report, "_MAX_RESULTS_BYTES", 10)
    with pytest.raises(SystemExit) as caught:
        report.main([str(source), "--output", str(output)])
    assert caught.value.code == 2
    assert not output.exists()


def test_cli_help_and_terminal_context_are_safe(tmp_path, capsys):
    with pytest.raises(SystemExit) as caught:
        report.main(["--help"])
    assert caught.value.code == 0
    assert "Examples:" in capsys.readouterr().out
    source = tmp_path / "results.json"
    source.write_text(json.dumps([_row(model="fixture\x1b[31m", bug_class="class\x1b[31m",
                                      function_id="function\x1b[31m", expected_mode_results={"security": "clean"})]))
    destination = tmp_path / "comparison.json"
    assert report.main([str(source), "--output", str(destination)]) == 0
    output = capsys.readouterr().out
    assert "Explicit mode expectations: 1 checked, 1 mismatches" in output
    assert "expected=clean got=suspicious" in output
    assert "\x1b" not in output
    saved = json.loads(destination.read_text())["runs"][0]["cohorts"][0]
    assert saved["mode_expectations"]["details"][0]["function_id"] == "function\x1b[31m"
