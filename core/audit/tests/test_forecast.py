"""Deepen-aware audit cost forecast — model + calibration tests.

Hermetic: pure model math over synthetic queue/prior/ledger shapes.
The fixture cost-breakdown documents mirror the on-disk shape the
ledger writes (phases + totals) with synthetic numbers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.forecast import (
    CALIBRATION_FILENAME,
    COLD_DENSITY_BAND,
    COLD_SUSPICIOUS_DENSITY,
    DEEPEN_CALLS_BAND,
    DEEPEN_CALLS_PER_SUSPICIOUS,
    FORECAST_FILENAME,
    PRIOR_DENSITY_BAND_FACTOR,
    REVIEW_BAND,
    SUPPORT_BAND,
    SUPPORT_FRAC,
    actual_phase_split,
    append_calibration,
    calibration_entry,
    filter_priors_to_checklist,
    forecast_audit_cost,
    format_calibration_line,
    format_forecast_lines,
    gap_slocs,
    load_forecast,
    predicted_suspicious_density,
    record_run_calibration,
    save_forecast,
    seed_rereview_mass,
)


def _gaps(files_functions: list[tuple[str, str]], sloc: int = 50):
    return [
        {"file": f, "name": n, "sloc": sloc,
         "line_start": 1, "line_end": sloc}
        for f, n in files_functions
    ]


def _forecast(gaps, priors=None, **kw):
    density = predicted_suspicious_density(gaps, priors)
    queue_keys = {(g["file"], g["name"]) for g in gaps}
    seed = seed_rereview_mass(priors, queue_keys)
    return forecast_audit_cost(
        slocs=gap_slocs(gaps), density=density, seed_mass=seed, **kw,
    )


def _breakdown(review=10.0, re_review=5.0, refinement=3.0,
               study=1.0, total=None):
    phases = {
        "review": {"cost_usd": review, "calls": 40, "tokens_in": 0,
                   "tokens_out": 0, "wall_time_s": 0.0},
        "re_review": {"cost_usd": re_review, "calls": 12},
        "refinement": {"cost_usd": refinement, "calls": 6},
        "study": {"cost_usd": study, "calls": 2},
        "prior_segments": {"cost_usd": 2.5, "calls": 0},
    }
    booked = review + re_review + refinement + study
    return {
        "phases": phases,
        "totals": {
            "cost_usd": booked,
            "total_spend_usd": total if total is not None else booked,
            "calls": 60,
        },
    }


# ---------------------------------------------------------------- model

class TestTwoDirectionBehavior:
    """The motivating property: a suspicious-dense queue must forecast
    materially more deepen spend than a clean-prior queue of the same
    shape, with the cold default in between."""

    def test_suspicious_dense_priors_forecast_higher_deepen(self):
        gaps = _gaps([("a.php", f"f{i}") for i in range(20)])
        dense = {("a.php", f"f{i}"): "suspicious" for i in range(20)}
        clean = {("a.php", f"f{i}"): "clean" for i in range(20)}

        fc_dense = _forecast(gaps, dense)
        fc_clean = _forecast(gaps, clean)
        fc_cold = _forecast(gaps, None)

        d = [fc["phases"]["deepen"]["usd_central"]
             for fc in (fc_clean, fc_cold, fc_dense)]
        assert d[0] < d[1] < d[2]
        assert fc_clean["usd_central"] < fc_cold["usd_central"] \
            < fc_dense["usd_central"]
        # And the clean direction really is cheap: no suspicious mass,
        # no deepen spend (the two-direction pin, not just ordering).
        assert fc_clean["phases"]["deepen"]["usd_central"] == 0.0

    def test_review_phase_is_density_independent(self):
        gaps = _gaps([("a.php", f"f{i}") for i in range(10)])
        dense = {("a.php", f"f{i}"): "suspicious" for i in range(10)}
        clean = {("a.php", f"f{i}"): "clean" for i in range(10)}
        assert (_forecast(gaps, dense)["phases"]["review"]
                == _forecast(gaps, clean)["phases"]["review"])


class TestForecastShape:
    def test_band_ordering(self):
        gaps = _gaps([("a.c", f"f{i}") for i in range(30)], sloc=120)
        fc = _forecast(gaps)
        assert fc["usd_low"] < fc["usd_central"] < fc["usd_high"]
        for phase in fc["phases"].values():
            assert phase["usd_low"] <= phase["usd_central"] \
                <= phase["usd_high"]

    def test_empty_queue_zero_review(self):
        fc = forecast_audit_cost(
            slocs=[],
            density=predicted_suspicious_density([], None),
            seed_mass=0,
        )
        assert fc["queue_n"] == 0
        assert fc["phases"]["review"]["usd_central"] == 0.0
        assert fc["usd_central"] == 0.0

    def test_seed_mass_adds_deepen_without_review(self):
        gaps = _gaps([("a.c", "f1")])
        base = _forecast(gaps, None)
        seeded = forecast_audit_cost(
            slocs=gap_slocs(gaps),
            density=predicted_suspicious_density(gaps, None),
            seed_mass=25,
        )
        assert seeded["phases"]["review"] == base["phases"]["review"]
        assert (seeded["phases"]["deepen"]["usd_central"]
                > base["phases"]["deepen"]["usd_central"])
        assert any("seeded re-review mass" in d for d in seeded["drivers"])

    def test_review_passes_scale_review_only(self):
        gaps = _gaps([("a.c", f"f{i}") for i in range(5)])
        one = _forecast(gaps, None, review_passes=1)
        three = _forecast(gaps, None, review_passes=3)
        assert three["phases"]["review"]["usd_central"] == pytest.approx(
            3 * one["phases"]["review"]["usd_central"])
        assert (three["phases"]["deepen"]["usd_central"]
                == one["phases"]["deepen"]["usd_central"])

    def test_model_override_noted_never_repriced(self):
        gaps = _gaps([("a.c", "f1")])
        plain = _forecast(gaps, None)
        overridden = _forecast(gaps, None, model_overrides=2)
        assert overridden["usd_central"] == plain["usd_central"]
        assert any("--model override" in d for d in overridden["drivers"])
        assert not any("--model override" in d for d in plain["drivers"])

    def test_sloc_cap_saturates(self):
        # Context slices stop growing with function size: per-item
        # review cost must saturate at the cap, not scale unbounded.
        from core.audit.forecast import REVIEW_SLOC_CAP
        density = predicted_suspicious_density([], None)
        at_cap = forecast_audit_cost(
            slocs=[REVIEW_SLOC_CAP], density=density, seed_mass=0)
        huge = forecast_audit_cost(
            slocs=[REVIEW_SLOC_CAP * 50], density=density, seed_mass=0)
        assert (huge["phases"]["review"]["usd_central"]
                == at_cap["phases"]["review"]["usd_central"])

    def test_sloc_monotonic(self):
        small = forecast_audit_cost(
            slocs=[10] * 10,
            density=predicted_suspicious_density([], None), seed_mass=0)
        large = forecast_audit_cost(
            slocs=[150] * 10,
            density=predicted_suspicious_density([], None), seed_mass=0)
        assert (large["phases"]["review"]["usd_central"]
                > small["phases"]["review"]["usd_central"])


class TestCoefficientContracts:
    """Both-directions pins on the seeded constants: the bands must
    bracket their centrals, and centrals must stay inside their bands
    — a re-fit that breaks either direction silently breaks the
    low<central<high contract everywhere downstream."""

    def test_multiplicative_bands_bracket_unity(self):
        for lo, hi in (REVIEW_BAND, SUPPORT_BAND,
                       PRIOR_DENSITY_BAND_FACTOR):
            assert 0 < lo <= hi
        assert REVIEW_BAND[0] < 1 < REVIEW_BAND[1]
        assert PRIOR_DENSITY_BAND_FACTOR[0] < 1 \
            < PRIOR_DENSITY_BAND_FACTOR[1]

    def test_absolute_bands_bracket_centrals(self):
        assert (DEEPEN_CALLS_BAND[0] < DEEPEN_CALLS_PER_SUSPICIOUS
                < DEEPEN_CALLS_BAND[1])
        assert (COLD_DENSITY_BAND[0] < COLD_SUSPICIOUS_DENSITY
                < COLD_DENSITY_BAND[1])
        assert 0 < COLD_SUSPICIOUS_DENSITY < 1
        assert SUPPORT_BAND[0] < SUPPORT_FRAC < SUPPORT_BAND[1]


# ------------------------------------------------------------- density

class TestPredictedDensity:
    def test_no_priors_is_cold(self):
        d = predicted_suspicious_density(_gaps([("a.c", "f")]), None)
        assert d["source"] == "cold"
        assert d["central"] == COLD_SUSPICIOUS_DENSITY
        assert (d["low"], d["high"]) == COLD_DENSITY_BAND
        assert d["prior_coverage"] == 0.0

    def test_empty_queue_is_cold(self):
        assert predicted_suspicious_density(
            [], {("a.c", "f"): "suspicious"})["source"] == "cold"

    def test_function_level_prior_wins_over_file_rate(self):
        gaps = _gaps([("a.c", "f1")])
        # File rate is 100% suspicious, but f1 itself was clean.
        priors = {("a.c", "f1"): "clean", ("a.c", "f2"): "suspicious"}
        d = predicted_suspicious_density(gaps, priors)
        assert d["central"] == 0.0
        assert d["source"] == "priors"
        assert d["prior_coverage"] == 1.0

    def test_file_rate_fallback(self):
        gaps = _gaps([("a.c", "new_fn")])
        priors = {("a.c", "f1"): "suspicious", ("a.c", "f2"): "clean"}
        d = predicted_suspicious_density(gaps, priors)
        assert d["central"] == pytest.approx(0.5)

    def test_uncovered_items_use_cold_default(self):
        gaps = _gaps([("unknown.c", "f")])
        priors = {("other.c", "g"): "clean"}
        d = predicted_suspicious_density(gaps, priors)
        assert d["central"] == pytest.approx(COLD_SUSPICIOUS_DENSITY)
        assert d["prior_coverage"] == 0.0

    def test_band_clamped_to_unit_interval(self):
        gaps = _gaps([("a.c", "f1")])
        d = predicted_suspicious_density(gaps, {("a.c", "f1"): "finding"})
        assert d["central"] == 1.0
        assert d["high"] == 1.0
        assert 0.0 <= d["low"] <= 1.0

    def test_finding_counts_as_suspicious_mass(self):
        gaps = _gaps([("a.c", "f1")])
        assert predicted_suspicious_density(
            gaps, {("a.c", "f1"): "finding"})["central"] == 1.0

    def test_dark_does_not_count_as_suspicious(self):
        gaps = _gaps([("a.c", "f1")])
        assert predicted_suspicious_density(
            gaps, {("a.c", "f1"): "dark"})["central"] == 0.0


class TestSeedMass:
    def test_counts_prior_suspicious_and_findings(self):
        priors = {("a.c", "f1"): "suspicious", ("a.c", "f2"): "finding",
                  ("a.c", "f3"): "clean", ("b.c", "g"): "dark"}
        assert seed_rereview_mass(priors) == 2

    def test_queue_members_excluded(self):
        priors = {("a.c", "f1"): "suspicious", ("a.c", "f2"): "suspicious"}
        assert seed_rereview_mass(priors, {("a.c", "f1")}) == 1

    def test_empty(self):
        assert seed_rereview_mass(None) == 0
        assert seed_rereview_mass({}) == 0


class TestRunScopedPriors:
    """filter_priors_to_checklist — the project index is project-wide;
    only rows in THIS run's (file, function) universe may price the
    density and seed-mass terms. A multi-binary project's index
    carries other targets' rows, which cannot re-enter this run's
    deepen phase and would only inflate the band."""

    @staticmethod
    def _checklist(files_functions: list[tuple[str, str]]) -> dict:
        by_file: dict[str, list[str]] = {}
        for f, n in files_functions:
            by_file.setdefault(f, []).append(n)
        return {
            "files": [
                {"path": f, "items": [{"name": n} for n in names]}
                for f, names in by_file.items()
            ],
        }

    def test_cross_target_excluded_same_target_retained(self):
        priors = {
            ("a.php", "f1"): "suspicious",
            ("a.php", "f2"): "clean",
            ("binary:other", "g1"): "suspicious",
            ("lib/other.c", "g2"): "finding",
        }
        kept = filter_priors_to_checklist(
            priors, self._checklist([("a.php", "f1"), ("a.php", "f2")]))
        assert kept == {
            ("a.php", "f1"): "suspicious",
            ("a.php", "f2"): "clean",
        }

    def test_seed_mass_computed_from_retained_keys_only(self):
        # Queue holds f1; f3 is a covered same-target suspicious prior
        # (legitimate seed mass); 50 cross-target suspicious rows must
        # contribute nothing.
        priors = {
            ("a.php", "f1"): "suspicious",
            ("a.php", "f3"): "suspicious",
        }
        priors.update({
            ("binary:other", f"g{i}"): "suspicious" for i in range(50)
        })
        checklist = self._checklist([("a.php", "f1"), ("a.php", "f3")])
        queue_keys = {("a.php", "f1")}
        # The pre-filter inflation this closes:
        assert seed_rereview_mass(priors, queue_keys) == 51
        kept = filter_priors_to_checklist(priors, checklist)
        assert seed_rereview_mass(kept, queue_keys) == 1

    def test_all_cross_target_priors_fall_back_to_cold_density(self):
        priors = {("binary:other", "g1"): "suspicious"}
        kept = filter_priors_to_checklist(
            priors, self._checklist([("a.php", "f1")]))
        assert kept == {}
        density = predicted_suspicious_density(
            _gaps([("a.php", "f1")]), kept)
        assert density["source"] == "cold"

    def test_functions_spelling_retained(self):
        # Checklist file entries may spell the item list "functions".
        checklist = {
            "files": [{"path": "a.c",
                       "functions": [{"name": "f1"}]}],
        }
        kept = filter_priors_to_checklist(
            {("a.c", "f1"): "suspicious"}, checklist)
        assert kept == {("a.c", "f1"): "suspicious"}

    def test_foreign_shapes_yield_empty(self):
        priors = {("a.php", "f1"): "suspicious"}
        assert filter_priors_to_checklist(priors, None) == {}
        assert filter_priors_to_checklist(priors, {"files": "junk"}) == {}
        assert filter_priors_to_checklist(
            priors, {"files": ["junk", {"path": 3, "items": None}]}) == {}
        assert filter_priors_to_checklist(None, {"files": []}) == {}
        assert filter_priors_to_checklist({}, {"files": []}) == {}


# --------------------------------------------------------- gap census

class TestGapSlocs:
    def test_hostile_shapes_degrade(self):
        gaps = [
            {"file": "a.c", "name": "f", "sloc": 40},
            {"file": "a.c", "name": "g", "line_start": 10, "line_end": 29},
            {"file": "a.c", "name": "h"},           # no size signal
            {"file": "a.c", "name": "i", "sloc": "40"},  # wrong type
            {"file": "a.c", "name": "j", "line_start": 30,
             "line_end": 10},                        # inverted range
            "not-a-dict",
            None,
        ]
        assert gap_slocs(gaps) == [40, 20, 0, 0, 0]

    def test_non_list(self):
        assert gap_slocs(None) == []
        assert gap_slocs({"gaps": []}) == []


# ---------------------------------------------------- actuals + records

class TestActualPhaseSplit:
    def test_three_phase_collapse(self):
        actual = actual_phase_split(_breakdown())
        assert actual["review_usd"] == 10.0
        assert actual["deepen_usd"] == 8.0          # re_review + refinement
        assert actual["deepen_calls"] == 18
        assert actual["support_usd"] == 1.0         # prior_segments excluded
        assert actual["total_spend_usd"] == 19.0

    def test_total_prefers_authoritative_ledger(self):
        actual = actual_phase_split(_breakdown(total=25.5))
        assert actual["total_spend_usd"] == 25.5

    def test_hostile_shapes(self):
        assert actual_phase_split({})["total_spend_usd"] == 0.0
        assert actual_phase_split(
            {"phases": "junk", "totals": []})["review_usd"] == 0.0
        junk = {"phases": {"review": "junk",
                           "re_review": {"cost_usd": "x", "calls": None}}}
        actual = actual_phase_split(junk)
        assert actual["review_usd"] == 0.0
        assert actual["deepen_usd"] == 0.0


class TestCalibration:
    def _fc(self):
        gaps = _gaps([("a.c", f"f{i}") for i in range(10)])
        return _forecast(gaps, None)

    def test_entry_within_band(self):
        fc = self._fc()
        bd = _breakdown(total=fc["usd_central"])
        entry = calibration_entry(fc, bd, run_id="run-1")
        assert entry["within_band"] is True
        assert entry["run_id"] == "run-1"
        assert entry["predicted"]["estimator"] == fc["estimator"]
        assert entry["actual"]["total_spend_usd"] == pytest.approx(
            fc["usd_central"], abs=0.01)
        assert entry["central_error_ratio"] == pytest.approx(1.0, abs=0.01)

    def test_entry_outside_band(self):
        fc = self._fc()
        bd = _breakdown(total=fc["usd_high"] * 10)
        entry = calibration_entry(fc, bd, run_id="run-2")
        assert entry["within_band"] is False
        assert entry["central_error_ratio"] > 1

    def test_append_is_one_json_line(self, tmp_path: Path):
        path = tmp_path / CALIBRATION_FILENAME
        entry = calibration_entry(self._fc(), _breakdown(), run_id="r")
        append_calibration(path, entry)
        append_calibration(path, entry)
        lines = path.read_text().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["run_id"] == "r"

    def test_append_respects_size_cap(self, tmp_path: Path,
                                      monkeypatch: pytest.MonkeyPatch):
        import core.audit.forecast as mod
        monkeypatch.setattr(mod, "_MAX_CALIBRATION_BYTES", 10)
        path = tmp_path / CALIBRATION_FILENAME
        path.write_text("x" * 100)
        append_calibration(path, {"a": 1})
        assert path.read_text() == "x" * 100


class TestRunCalibrationTail:
    def _run_dir(self, tmp_path: Path, *, forecast_only=False,
                 with_breakdown=True) -> Path:
        run_dir = tmp_path / "project" / "run-1"
        run_dir.mkdir(parents=True)
        fc = _forecast(_gaps([("a.c", "f1")] * 3), None)
        save_forecast(run_dir, fc, forecast_only=forecast_only)
        if with_breakdown:
            (run_dir / "cost-breakdown.json").write_text(
                json.dumps(_breakdown()))
        return run_dir

    def test_records_run_and_project_level(self, tmp_path: Path):
        run_dir = self._run_dir(tmp_path)
        project_dir = run_dir.parent
        from core.coverage.journal import INDEX_FILENAME
        (project_dir / INDEX_FILENAME).write_text("{}")
        entry = record_run_calibration(run_dir)
        assert entry is not None
        assert (run_dir / CALIBRATION_FILENAME).is_file()
        project_lines = (
            project_dir / CALIBRATION_FILENAME).read_text().splitlines()
        assert json.loads(project_lines[0])["run_id"] == "run-1"

    def test_no_project_marker_stays_run_local(self, tmp_path: Path):
        run_dir = self._run_dir(tmp_path)
        assert record_run_calibration(run_dir) is not None
        assert (run_dir / CALIBRATION_FILENAME).is_file()
        assert not (run_dir.parent / CALIBRATION_FILENAME).exists()

    def test_forecast_only_run_records_nothing(self, tmp_path: Path):
        run_dir = self._run_dir(tmp_path, forecast_only=True)
        assert record_run_calibration(run_dir) is None
        assert not (run_dir / CALIBRATION_FILENAME).exists()

    def test_missing_breakdown_records_nothing(self, tmp_path: Path):
        run_dir = self._run_dir(tmp_path, with_breakdown=False)
        assert record_run_calibration(run_dir) is None

    def test_no_forecast_records_nothing(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "cost-breakdown.json").write_text(
            json.dumps(_breakdown()))
        assert record_run_calibration(run_dir) is None

    def test_corrupt_forecast_never_raises(self, tmp_path: Path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / FORECAST_FILENAME).write_text("{corrupt")
        (run_dir / "cost-breakdown.json").write_text(
            json.dumps(_breakdown()))
        assert record_run_calibration(run_dir) is None


class TestPersistence:
    def test_save_load_round_trip(self, tmp_path: Path):
        fc = _forecast(_gaps([("a.c", "f1")]), None)
        save_forecast(tmp_path, fc)
        loaded = load_forecast(tmp_path)
        assert loaded is not None
        assert loaded["outcome"] == "pre_run"
        assert loaded["usd_central"] == fc["usd_central"]

    def test_forecast_only_marker(self, tmp_path: Path):
        save_forecast(tmp_path, _forecast(_gaps([("a.c", "f")]), None),
                      forecast_only=True)
        assert load_forecast(tmp_path)["outcome"] == "forecast_only"

    def test_load_missing_and_corrupt(self, tmp_path: Path):
        assert load_forecast(tmp_path) is None
        (tmp_path / FORECAST_FILENAME).write_text("[1, 2]")
        assert load_forecast(tmp_path) is None


# -------------------------------------------------------------- output

class TestFormatting:
    def test_forecast_lines(self):
        fc = _forecast(_gaps([("a.c", f"f{i}") for i in range(7)]), None)
        lines = format_forecast_lines(fc)
        head = lines[0]
        assert head.startswith("Cost forecast: $")
        assert "not a cap" in head
        assert "7 queue item(s)" in head
        # Never ALL_CAPS status vocabulary; never budget language.
        assert "central split" in lines[1]
        body = "\n".join(lines)
        assert "band driver" in body
        assert "cold suspicious-density default" in body

    def test_priors_driver_named(self):
        gaps = _gaps([("a.c", "f1")])
        fc = _forecast(gaps, {("a.c", "f1"): "clean"})
        assert any("journal priors" in d for d in fc["drivers"])

    def test_calibration_line(self):
        fc = _forecast(_gaps([("a.c", "f")] * 5), None)
        entry = calibration_entry(
            fc, _breakdown(total=fc["usd_central"]), run_id="r")
        line = format_calibration_line(entry)
        assert "Forecast vs actual" in line
        assert "within band" in line
        entry_out = calibration_entry(
            fc, _breakdown(total=fc["usd_high"] * 10), run_id="r")
        assert "OUTSIDE band" in format_calibration_line(entry_out)

    def test_calibration_line_exact_when_valid(self):
        """Direction 1: a well-formed entry renders exact figures."""
        fc = _forecast(_gaps([("a.c", "f")] * 5), None)
        entry = calibration_entry(
            fc, _breakdown(total=fc["usd_central"]), run_id="r")
        line = format_calibration_line(entry)
        assert f"${fc['usd_low']:.2f}-${fc['usd_high']:.2f}" in line
        assert f"(central ~${fc['usd_central']:.2f})" in line
        assert "$?" not in line

    def test_calibration_line_partial_forecast_degrades_loudly(self):
        """Direction 2: keys present with ``None`` values (the
        parseable-but-partial forecast.json shape) must render as a
        visible ``$?`` marker, never raise at the print seam."""
        entry = {
            "predicted": {"usd_low": None, "usd_high": None,
                          "usd_central": None},
            "actual": {},
            "within_band": None,
            "central_error_ratio": None,
        }
        line = format_calibration_line(entry)
        assert line.count("$?") == 4  # low, high, central, actual
        assert "Forecast vs actual" in line

    def test_calibration_line_hostile_shapes_never_raise(self):
        for entry in (
            {},
            {"predicted": "not-a-dict", "actual": 3},
            {"predicted": {"usd_low": "12"}, "actual": {
                "total_spend_usd": True}},
            {"within_band": "yes", "central_error_ratio": "2x"},
        ):
            line = format_calibration_line(entry)
            assert "Forecast vs actual" in line
            assert "$?" in line
