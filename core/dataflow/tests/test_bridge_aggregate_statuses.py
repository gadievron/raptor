"""Unknown persisted statuses remain errors rather than adjudicated outcomes."""

import pytest

from core.dataflow.cvefix_bridge import _aggregate


class OwnedRows:
    def __init__(self, rows):
        self.rows = rows
        self.reads = 0

    def execute(self, query):
        assert query == "SELECT status, finding_id FROM synth_results"
        self.reads += 1
        return iter(self.rows)


def test_unknown_status_is_excluded_and_disclosed_with_pipeline_errors():
    source = OwnedRows([
        ("sound", "owned-sound"), ("not_sound", "owned-not-sound"),
        ("no_barrier", "owned-no-barrier"), ("build_fail", None),
        ("unrecognised-owned-status", "owned-unknown"),
    ])
    report, errors = _aggregate(source)
    assert source.reads == 1
    assert report.total == 3
    assert (report.sound, report.not_sound, report.no_barrier) == (1, 1, 1)
    assert report.suppression_rate == pytest.approx(1 / 3)
    assert report.per_finding == (
        ("owned-sound", "sound"), ("owned-not-sound", "not_sound"),
        ("owned-no-barrier", "no_barrier"),
    )
    assert errors == {"build_fail": 1, "unrecognised-owned-status": 1}


def test_unknown_only_has_no_adjudicated_rate():
    report, errors = _aggregate(OwnedRows([("unrecognised-owned-status", None)]))
    assert report.total == 0
    assert report.per_finding == ()
    assert report.suppression_rate is None
    assert errors == {"unrecognised-owned-status": 1}


def test_known_outcomes_keep_existing_counts():
    report, errors = _aggregate(OwnedRows([("sound", "owned-1"), ("no_barrier", "owned-2")]))
    assert (report.total, report.sound, report.not_sound, report.no_barrier) == (2, 1, 0, 1)
    assert report.suppression_rate == 0.5
    assert errors == {}
