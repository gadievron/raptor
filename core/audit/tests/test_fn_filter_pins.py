"""Tests for the --functions filter vs operator-pin interaction.

Regression: a calibration run pinned every labeled function and passed
line-scoped ``--functions`` specs whose line numbers had drifted from
the pinned source. The ±3 line tolerance dropped every pinned gap from
the workqueue, so the "guaranteed review slot" never produced a review.
Pinned gaps must survive the filter.
"""

from __future__ import annotations

from core.audit.orchestrator import _fn_filter_keep, _fn_filter_match


def _gap(file="a.c", name="f", line=100, *, pinned=False, class_name=None):
    gap = {"file": file, "name": name, "line_start": line}
    if pinned:
        gap["pinned"] = True
    if class_name:
        gap["metadata"] = {"class_name": class_name}
    return gap


def _filter(simple=(), lined=None):
    return (set(simple), {k: set(v) for k, v in (lined or {}).items()})


class TestFnFilterMatch:
    def test_simple_spec_matches(self):
        assert _fn_filter_match(_gap(), _filter(simple={"a.c:f"}))

    def test_simple_spec_rejects_other_function(self):
        assert not _fn_filter_match(_gap(name="g"), _filter(simple={"a.c:f"}))

    def test_lined_spec_matches_within_tolerance(self):
        assert _fn_filter_match(
            _gap(line=102), _filter(lined={"a.c:f": [100]}),
        )

    def test_lined_spec_rejects_drifted_line(self):
        assert not _fn_filter_match(
            _gap(line=544), _filter(lined={"a.c:f": [450]}),
        )

    def test_class_qualified_spec_matches_via_metadata(self):
        gap = _gap(file="m.py", name="check", class_name="Manager")
        assert _fn_filter_match(gap, _filter(simple={"m.py:Manager.check"}))


class TestFnFilterKeep:
    def test_unpinned_drifted_line_is_dropped(self):
        assert not _fn_filter_keep(
            _gap(line=544), _filter(lined={"a.c:f": [450]}),
        )

    def test_pinned_gap_survives_drifted_line(self):
        # The corpus defect: label line 450 vs source line 544 — the
        # pin is an explicit review order and must be kept.
        assert _fn_filter_keep(
            _gap(line=544, pinned=True), _filter(lined={"a.c:f": [450]}),
        )

    def test_pinned_gap_survives_absent_spec(self):
        assert _fn_filter_keep(
            _gap(pinned=True), _filter(simple={"b.c:other"}),
        )

    def test_matching_gap_kept_without_pin(self):
        assert _fn_filter_keep(_gap(), _filter(simple={"a.c:f"}))
