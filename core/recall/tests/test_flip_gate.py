"""Flip gate: three checks, fail-closed pairing, number-free stdout."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.recall.cli import main as cli_main
from core.recall.flip_gate import (
    CHECK_NAMES,
    FlipGateError,
    evaluate_flip_gate,
    load_reports,
    render_public,
)
from core.recall.score import LABEL_CLASS


def _report(manifest="m1", *, found=3, expected=5, fps=1,
            missed_ids=("e4", "e5"), sha="a" * 40,
            profile="agentic", clean_total=4,
            digest="d" * 64) -> dict[str, Any]:
    return {
        "label_class": LABEL_CLASS,
        "manifest": manifest,
        "language": "python",
        "profile": profile,
        "pinned_sha": sha,
        "recall": found / expected if expected else None,
        "expected_total": expected,
        "found_total": found,
        "per_cwe": [],
        "missed": [{"id": i, "file": f"{i}.py", "cwe": "CWE-89"}
                   for i in missed_ids],
        "clean_region_fp_count": fps,
        "clean_region_fps": [],
        "clean_region_total": clean_total,
        "label_digest": digest,
    }


def _sides(**cand_kw):
    base = {"m1": _report()}
    cand = {"m1": _report(profile="agentic-taint", **cand_kw)}
    return base, cand


class TestChecks:
    def test_all_three_pass(self):
        base, cand = _sides(found=4, missed_ids=("e5",), fps=1)
        result = evaluate_flip_gate(base, cand)
        assert result["passed"]
        assert all(result["checks"][n]["passed"] for n in CHECK_NAMES)

    def test_no_uplift_fails_recall_check(self):
        base, cand = _sides()  # identical counts
        result = evaluate_flip_gate(base, cand)
        assert not result["passed"]
        assert not result["checks"]["recall_uplift"]["passed"]
        assert result["checks"]["no_displacement"]["passed"]

    def test_min_uplift_margin_is_strict(self):
        base, cand = _sides(found=4, missed_ids=("e5",))
        # uplift is exactly 0.2; a margin of 0.2 must NOT pass.
        result = evaluate_flip_gate(base, cand, min_uplift=0.2)
        assert not result["checks"]["recall_uplift"]["passed"]
        result = evaluate_flip_gate(base, cand, min_uplift=0.19)
        assert result["checks"]["recall_uplift"]["passed"]

    def test_fp_growth_fails_ceiling(self):
        base, cand = _sides(found=5, missed_ids=(), fps=3)
        result = evaluate_flip_gate(base, cand)
        assert not result["passed"]
        assert not result["checks"]["clean_region_fp_ceiling"]["passed"]
        # ...and the pinned ceiling admits exactly the allowed growth.
        result = evaluate_flip_gate(base, cand, fp_ceiling=2)
        assert result["checks"]["clean_region_fp_ceiling"]["passed"]

    def test_displacement_fails_even_with_uplift(self):
        # Candidate gains two findings but LOSES a baseline-matched
        # one: net recall is up, the gate must still fail — the
        # regression is invisible to a standalone recall number.
        base, cand = _sides(found=4, missed_ids=("e1",))
        result = evaluate_flip_gate(base, cand)
        assert result["checks"]["recall_uplift"]["passed"]
        assert not result["checks"]["no_displacement"]["passed"]
        assert not result["passed"]
        assert result["checks"]["no_displacement"]["displaced"] == {
            "m1": ["e1"]}

    def test_aggregates_across_manifests(self):
        base = {"m1": _report("m1"), "m2": _report("m2", sha="b" * 40)}
        cand = {
            "m1": _report("m1", found=3,                  # flat
                          profile="agentic-taint"),
            "m2": _report("m2", found=5, missed_ids=(),   # up
                          sha="b" * 40, profile="agentic-taint"),
        }
        result = evaluate_flip_gate(base, cand)
        agg = result["checks"]["recall_uplift"]
        assert agg["baseline_found"] == 6
        assert agg["candidate_found"] == 8
        assert agg["expected_total"] == 10
        assert result["passed"]
        assert len(result["manifests"]) == 2


class TestFailClosedPairing:
    def test_unpaired_manifests_refused(self):
        base = {"m1": _report("m1"), "m2": _report("m2")}
        cand = {"m1": _report("m1")}
        with pytest.raises(FlipGateError, match="manifest sets differ"):
            evaluate_flip_gate(base, cand)
        with pytest.raises(FlipGateError, match="manifest sets differ"):
            evaluate_flip_gate(cand, base)

    def test_sha_drift_refused(self):
        base, cand = _sides(sha="b" * 40)
        with pytest.raises(FlipGateError, match="pinned_sha"):
            evaluate_flip_gate(base, cand)

    def test_label_set_drift_refused(self):
        base, cand = _sides(found=4, expected=6)
        with pytest.raises(FlipGateError, match="expected_total"):
            evaluate_flip_gate(base, cand)

    def test_zero_expected_refused(self):
        base = {"m1": _report(found=0, expected=0, missed_ids=())}
        cand = {"m1": _report(found=0, expected=0, missed_ids=(),
                              profile="agentic-taint")}
        with pytest.raises(FlipGateError, match="zero expected"):
            evaluate_flip_gate(base, cand)

    def test_negative_knobs_refused(self):
        base, cand = _sides()
        with pytest.raises(FlipGateError, match="fp_ceiling"):
            evaluate_flip_gate(base, cand, fp_ceiling=-1)
        with pytest.raises(FlipGateError, match="min_uplift"):
            evaluate_flip_gate(base, cand, min_uplift=-0.1)


class TestDeclaredProfilePair:
    def test_baseline_profile_mismatch_refused(self):
        # A mis-frozen baseline (wrong profile) must never manufacture
        # unattributable uplift.
        base = {"m1": _report(profile="scan")}
        cand = {"m1": _report(found=4, missed_ids=("e5",),
                              profile="agentic-taint")}
        with pytest.raises(FlipGateError,
                           match="declared baseline profile"):
            evaluate_flip_gate(base, cand)

    def test_identical_profiles_refused_under_default_declaration(self):
        base = {"m1": _report()}
        cand = {"m1": _report(found=4, missed_ids=("e5",))}  # agentic
        with pytest.raises(FlipGateError,
                           match="declared candidate profile"):
            evaluate_flip_gate(base, cand)

    def test_explicitly_declared_same_profile_pair_accepted(self):
        # Build-vs-build comparisons (--pipeline-dir) are legitimate
        # when the operator declares the pair.
        base = {"m1": _report()}
        cand = {"m1": _report(found=4, missed_ids=("e5",))}
        result = evaluate_flip_gate(base, cand,
                                    profiles=("agentic", "agentic"))
        assert result["passed"]
        assert result["profiles"] == {"baseline": "agentic",
                                      "candidate": "agentic"}

    def test_unknown_declared_profile_refused(self):
        base, cand = _sides(found=4, missed_ids=("e5",))
        with pytest.raises(FlipGateError, match="not a known"):
            evaluate_flip_gate(
                base, cand, profiles=("agentic", "agentic-tain"))
        with pytest.raises(FlipGateError, match="not a known"):
            evaluate_flip_gate(
                base, cand, profiles=("scam", "agentic-taint"))

    def test_result_records_the_declared_pair(self):
        base, cand = _sides(found=4, missed_ids=("e5",))
        result = evaluate_flip_gate(base, cand)
        assert result["profiles"] == {"baseline": "agentic",
                                      "candidate": "agentic-taint"}
        assert result["legacy_baseline"] is False


class TestReportConsistencyGuards:
    def test_missing_fp_count_refused_on_either_side(self):
        # A truncated report must never read as zero clean-region FPs.
        for side in ("baseline", "candidate"):
            base, cand = _sides(found=4, missed_ids=("e5",))
            victim = base["m1"] if side == "baseline" else cand["m1"]
            del victim["clean_region_fp_count"]
            with pytest.raises(FlipGateError,
                               match="clean_region_fp_count missing"):
                evaluate_flip_gate(base, cand)

    def test_non_int_fp_count_refused(self):
        base, cand = _sides(found=4, missed_ids=("e5",))
        cand["m1"]["clean_region_fp_count"] = "0"
        with pytest.raises(FlipGateError,
                           match="clean_region_fp_count missing"):
            evaluate_flip_gate(base, cand)

    def test_found_total_above_expected_refused(self):
        base, cand = _sides(found=9, missed_ids=())
        with pytest.raises(FlipGateError, match="out of range"):
            evaluate_flip_gate(base, cand)

    def test_found_total_missed_list_inconsistency_refused(self):
        # Claims it found everything AND missed everything.
        base, cand = _sides(
            found=5, missed_ids=("e1", "e2", "e3", "e4", "e5"))
        with pytest.raises(FlipGateError, match="missed count"):
            evaluate_flip_gate(base, cand)

    def test_missing_missed_list_refused_when_inconsistent(self):
        base, cand = _sides(found=4)
        del cand["m1"]["missed"]
        with pytest.raises(FlipGateError, match="missed count"):
            evaluate_flip_gate(base, cand)

    def test_fp_count_above_clean_region_total_refused(self):
        base, cand = _sides(found=4, missed_ids=("e5",), fps=9)
        with pytest.raises(FlipGateError, match="exceeds"):
            evaluate_flip_gate(base, cand)


class TestLabelSetPins:
    def test_clean_region_total_drift_refused(self):
        # The finding-inflation route: pruning clean_regions between
        # freeze and candidate run blinds the FP ceiling while
        # pinned_sha + expected_total still match.
        base, cand = _sides(found=4, missed_ids=("e5",),
                            clean_total=2, digest="e" * 64)
        with pytest.raises(FlipGateError,
                           match="clean_region_total differs"):
            evaluate_flip_gate(base, cand)

    def test_label_digest_drift_refused(self):
        base, cand = _sides(found=4, missed_ids=("e5",),
                            digest="e" * 64)
        with pytest.raises(FlipGateError, match="label_digest differs"):
            evaluate_flip_gate(base, cand)

    def test_legacy_baseline_refused_by_default(self):
        base, cand = _sides(found=4, missed_ids=("e5",))
        for key in ("clean_region_total", "label_digest"):
            del base["m1"][key]
        with pytest.raises(FlipGateError,
                           match="allow-legacy-baseline"):
            evaluate_flip_gate(base, cand)

    def test_legacy_baseline_grandfathered_with_flag(self):
        base, cand = _sides(found=4, missed_ids=("e5",))
        for key in ("clean_region_total", "label_digest"):
            del base["m1"][key]
        result = evaluate_flip_gate(base, cand,
                                    allow_legacy_baseline=True)
        assert result["passed"]
        assert result["legacy_baseline"] is True
        text = render_public(result)
        assert "legacy-baseline" in text
        assert not any(ch.isdigit() for ch in text)

    def test_candidate_pins_never_grandfathered(self):
        base, cand = _sides(found=4, missed_ids=("e5",))
        for key in ("clean_region_total", "label_digest"):
            del cand["m1"][key]
        with pytest.raises(FlipGateError, match="candidate report"):
            evaluate_flip_gate(base, cand,
                               allow_legacy_baseline=True)

    def test_partial_pins_never_grandfathered(self):
        # One pin present + one absent is not a legacy report.
        for keep in ("clean_region_total", "label_digest"):
            base, cand = _sides(found=4, missed_ids=("e5",))
            for key in ("clean_region_total", "label_digest"):
                if key != keep:
                    del base["m1"][key]
            with pytest.raises(FlipGateError, match="missing"):
                evaluate_flip_gate(base, cand,
                                   allow_legacy_baseline=True)

    def test_mismatched_pins_refuse_even_with_flag(self):
        base, cand = _sides(found=4, missed_ids=("e5",),
                            digest="e" * 64)
        with pytest.raises(FlipGateError, match="label_digest differs"):
            evaluate_flip_gate(base, cand,
                               allow_legacy_baseline=True)


class TestLoadReports:
    def test_dir_scan_skips_sibling_artifacts(self, tmp_path):
        (tmp_path / "report.json").write_text(
            json.dumps(_report()), encoding="utf-8")
        (tmp_path / "census.json").write_text(
            json.dumps({"idioms": []}), encoding="utf-8")
        (tmp_path / "notes.json").write_text("[1, 2]", encoding="utf-8")
        got = load_reports(tmp_path)
        assert set(got) == {"m1"}

    def test_empty_side_refused(self, tmp_path):
        (tmp_path / "census.json").write_text("{}", encoding="utf-8")
        with pytest.raises(FlipGateError, match="no recall reports"):
            load_reports(tmp_path)

    def test_duplicate_manifest_name_refused(self, tmp_path):
        for name in ("a.json", "b.json"):
            (tmp_path / name).write_text(json.dumps(_report()),
                                         encoding="utf-8")
        with pytest.raises(FlipGateError, match="two reports"):
            load_reports(tmp_path)

    def test_single_file_must_be_a_report(self, tmp_path):
        p = tmp_path / "x.json"
        p.write_text("{}", encoding="utf-8")
        with pytest.raises(FlipGateError, match="not a recall report"):
            load_reports(p)

    def test_missing_path_refused(self, tmp_path):
        with pytest.raises(FlipGateError, match="not a file"):
            load_reports(tmp_path / "absent")


class TestHideGaps:
    def test_public_render_carries_no_numbers(self):
        base, cand = _sides(found=4, missed_ids=("e1",), fps=3)
        result = evaluate_flip_gate(base, cand, fp_ceiling=1)
        text = render_public(result, Path("gate-out/report.json"))
        assert "flip-gate: FAIL" in text
        for name in CHECK_NAMES:
            assert name in text
        # No digit anywhere: no recall figures, counts, or label ids
        # leak to stdout (the report path above is digit-free on
        # purpose — the check covers the whole rendered text).
        assert not any(ch.isdigit() for ch in text)
        # ...and no label id either.
        assert "e1" not in text
        # The declared profile pair IS printed (mechanism names from
        # the closed vocabulary, not report content).
        assert "profiles: agentic -> agentic-taint" in text

    def test_numbers_live_in_the_report(self):
        base, cand = _sides(found=4, missed_ids=("e1",))
        result = evaluate_flip_gate(base, cand)
        assert result["checks"]["recall_uplift"]["uplift"] == \
            pytest.approx(0.2)
        assert result["label_class"] == LABEL_CLASS


class TestCli:
    def _write_side(self, d: Path, report: dict[str, Any]) -> Path:
        d.mkdir(parents=True, exist_ok=True)
        (d / "report.json").write_text(json.dumps(report),
                                       encoding="utf-8")
        return d

    def test_pass_exit_zero_and_report_written(self, tmp_path, capsys):
        base = self._write_side(tmp_path / "baseline", _report())
        cand = self._write_side(
            tmp_path / "cand",
            _report(found=5, missed_ids=(), profile="agentic-taint"))
        rc = cli_main(["flip-gate", "--baseline", str(base),
                       "--candidate", str(cand)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "flip-gate: PASS" in out
        report = json.loads(
            (cand / "flip-gate-report.json").read_text())
        assert report["passed"]
        assert report["checks"]["recall_uplift"]["candidate_found"] == 5

    def test_fail_exit_one(self, tmp_path, capsys):
        base = self._write_side(tmp_path / "baseline", _report())
        cand = self._write_side(
            tmp_path / "cand", _report(profile="agentic-taint"))
        rc = cli_main(["flip-gate", "--baseline", str(base),
                       "--candidate", str(cand)])
        assert rc == 1
        assert "flip-gate: FAIL" in capsys.readouterr().out

    def test_incomparable_exit_two(self, tmp_path, capsys):
        base = self._write_side(tmp_path / "baseline", _report())
        cand = self._write_side(
            tmp_path / "cand",
            _report(sha="b" * 40, profile="agentic-taint"))
        rc = cli_main(["flip-gate", "--baseline", str(base),
                       "--candidate", str(cand)])
        assert rc == 2
        assert "pinned_sha" in capsys.readouterr().err

    def test_declared_profile_flags(self, tmp_path, capsys):
        # scan -> scan-codeql declared explicitly: the reports carry
        # those profiles, so the default declaration would refuse.
        base = self._write_side(tmp_path / "baseline",
                                _report(profile="scan"))
        cand = self._write_side(
            tmp_path / "cand",
            _report(found=5, missed_ids=(), profile="scan-codeql"))
        rc = cli_main(["flip-gate", "--baseline", str(base),
                       "--candidate", str(cand),
                       "--baseline-profile", "scan",
                       "--candidate-profile", "scan-codeql"])
        assert rc == 0
        assert "profiles: scan -> scan-codeql" in capsys.readouterr().out

    def test_profile_mismatch_exit_two(self, tmp_path, capsys):
        base = self._write_side(tmp_path / "baseline",
                                _report(profile="scan"))
        cand = self._write_side(
            tmp_path / "cand",
            _report(found=5, missed_ids=(), profile="agentic-taint"))
        rc = cli_main(["flip-gate", "--baseline", str(base),
                       "--candidate", str(cand)])
        assert rc == 2
        assert "declared baseline profile" in capsys.readouterr().err

    def test_allow_legacy_baseline_flag(self, tmp_path, capsys):
        legacy = _report()
        for key in ("clean_region_total", "label_digest"):
            del legacy[key]
        base = self._write_side(tmp_path / "baseline", legacy)
        cand = self._write_side(
            tmp_path / "cand",
            _report(found=5, missed_ids=(), profile="agentic-taint"))
        rc = cli_main(["flip-gate", "--baseline", str(base),
                       "--candidate", str(cand)])
        assert rc == 2  # refused without the flag
        rc = cli_main(["flip-gate", "--baseline", str(base),
                       "--candidate", str(cand),
                       "--allow-legacy-baseline"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "legacy-baseline" in out
        report = json.loads(
            (cand / "flip-gate-report.json").read_text())
        assert report["legacy_baseline"] is True

    def test_explicit_report_path(self, tmp_path):
        base = self._write_side(tmp_path / "baseline", _report())
        cand = self._write_side(
            tmp_path / "cand",
            _report(found=5, missed_ids=(), profile="agentic-taint"))
        report = tmp_path / "reports" / "gate.json"
        rc = cli_main(["flip-gate", "--baseline", str(base),
                       "--candidate", str(cand),
                       "--report", str(report)])
        assert rc == 0
        assert json.loads(report.read_text())["passed"]
