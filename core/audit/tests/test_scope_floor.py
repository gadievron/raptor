"""Scoped-run coverage floor + zero-slot reporting (item 7).

The final comparison audit ran ``--scope crypto/bio --budget 40``; the
priority scorer gave 19 of ~26 in-scope files all the slots and one
zero-slot file carried a real finding that was missed entirely — with
no signal anywhere that the file had been starved. These tests pin the
gap-selection layer: floor ON guarantees every in-scope file one slot
(when files fit in the budget); floor OFF (or overflow) keeps the
score cut but reports the zero-slot files loudly and persists the
report for the run summary and tier diagnostics.
"""

from __future__ import annotations

import json
import logging

from core.audit.gaps import truncate_gaps_to_budget


def _gap(file, name, priority=0, sloc=10):
    return {
        "file": file, "name": name, "line_start": 1, "line_end": sloc,
        "priority": priority, "strategies": ["general"],
        "is_stale": False, "sloc": sloc,
    }


def _starving_fixture():
    """Score order that starves c.c under budget 4: a.c and b.c own
    the first four slots."""
    return [
        _gap("a.c", "a1"), _gap("a.c", "a2"), _gap("a.c", "a3"),
        _gap("b.c", "b1"), _gap("b.c", "b2"),
        _gap("c.c", "c1"),  # the bio_print.c shape: best gap ranks last
    ]


class TestFloorOn:
    def test_floor_assigns_every_file_a_slot(self, tmp_path):
        gaps = _starving_fixture()
        selected = truncate_gaps_to_budget(
            gaps, 4, tmp_path, scope=["src"], scope_floor=True,
        )
        assert len(selected) == 4
        files = {g["file"] for g in selected}
        assert files == {"a.c", "b.c", "c.c"}
        # The floored slot is the file's best-scored gap.
        assert any(g["name"] == "c1" for g in selected)
        # Remaining budget went to score order.
        names = [g["name"] for g in selected]
        assert names[0] == "a1"

    def test_floor_report_written(self, tmp_path):
        truncate_gaps_to_budget(
            _starving_fixture(), 4, tmp_path,
            scope=["src"], scope_floor=True,
        )
        report = json.loads((tmp_path / "scope-coverage.json").read_text())
        assert report["zero_slot_files"] == []
        assert report["floor_applied"] is True
        assert report["in_scope_files"] == 3
        assert report["files_with_slots"] == 3

    def test_overflow_skips_floor_and_reports(self, tmp_path, caplog):
        """More in-scope files than budget: floor cannot help — plain
        score cut, and the loud report carries the overflow."""
        gaps = [_gap(f"f{i}.c", f"fn{i}") for i in range(6)]
        with caplog.at_level(logging.WARNING, logger="core.audit.gaps"):
            selected = truncate_gaps_to_budget(
                gaps, 3, tmp_path, scope=["src"], scope_floor=True,
            )
        assert len(selected) == 3
        report = json.loads((tmp_path / "scope-coverage.json").read_text())
        assert report["overflow"] is True
        assert report["floor_applied"] is False
        assert len(report["zero_slot_files"]) == 3
        assert "outnumber" in caplog.text
        assert "ZERO review slots" in caplog.text


class TestFloorOff:
    def test_score_cut_kept_but_zero_slot_files_reported(
        self, tmp_path, caplog,
    ):
        gaps = _starving_fixture()
        with caplog.at_level(logging.WARNING, logger="core.audit.gaps"):
            selected = truncate_gaps_to_budget(
                gaps, 4, tmp_path, scope=["src"], scope_floor=False,
            )
        # Pure score order: c.c starved (the pre-fix behaviour) —
        # but never silently.
        assert {g["file"] for g in selected} == {"a.c", "b.c"}
        report = json.loads((tmp_path / "scope-coverage.json").read_text())
        assert report["zero_slot_files"] == ["c.c"]
        assert "ZERO review slots" in caplog.text
        assert "c.c" in caplog.text


class TestUnscopedUnchanged:
    def test_no_scope_keeps_plain_truncation(self, tmp_path):
        gaps = _starving_fixture()
        selected = truncate_gaps_to_budget(gaps, 4, tmp_path)
        assert [g["name"] for g in selected] == ["a1", "a2", "a3", "b1"]
        assert not (tmp_path / "scope-coverage.json").exists()

    def test_not_attempted_recording_preserved(self, tmp_path):
        truncate_gaps_to_budget(
            _starving_fixture(), 4, tmp_path,
            scope=["src"], scope_floor=True,
        )
        rec = json.loads((tmp_path / "not-attempted.json").read_text())
        assert rec["count"] == 2  # 6 gaps, 4 slots

    def test_within_budget_scoped_writes_all_covered_report(self, tmp_path):
        gaps = _starving_fixture()
        selected = truncate_gaps_to_budget(
            gaps, 10, tmp_path, scope=["src"], scope_floor=True,
        )
        assert selected == gaps
        report = json.loads((tmp_path / "scope-coverage.json").read_text())
        assert report["zero_slot_files"] == []


class TestTierDiagnosticsMerge:
    def test_scope_coverage_surfaces_in_tier_diagnostics(self, tmp_path):
        from core.audit.diagnostics import write_tier_diagnostics

        truncate_gaps_to_budget(
            _starving_fixture(), 4, tmp_path,
            scope=["src"], scope_floor=False,
        )
        write_tier_diagnostics({}, tmp_path)
        diag = json.loads((tmp_path / "tier-diagnostics.json").read_text())
        assert diag["scope_coverage"]["zero_slot_files"] == ["c.c"]


class TestHoistPins:
    """--pin: guaranteed slots, hoisted ahead of the budget cut."""

    def _gaps(self):
        return [
            {"file": "a.c", "name": "high", "priority": 1},
            {"file": "a.c", "name": "mid", "priority": 2},
            {"file": "b.c", "name": "low", "priority": 3},
            {"file": "b.c", "name": "target", "priority": 4},
        ]

    def test_pin_moves_to_front(self):
        from core.audit.gaps import hoist_pins
        out = hoist_pins(self._gaps(), ["b.c:target"])
        assert out[0]["name"] == "target"
        assert [g["name"] for g in out[1:]] == ["high", "mid", "low"]

    def test_pin_survives_budget_cut(self, tmp_path):
        from core.audit.gaps import hoist_pins, truncate_gaps_to_budget
        out = hoist_pins(self._gaps(), ["b.c:target"])
        kept = truncate_gaps_to_budget(out, 2, tmp_path)
        assert {g["name"] for g in kept} == {"target", "high"}

    def test_pin_becomes_file_floor_slot(self, tmp_path):
        from core.audit.gaps import hoist_pins, truncate_gaps_to_budget
        out = hoist_pins(self._gaps(), ["b.c:target"])
        kept = truncate_gaps_to_budget(
            out, 2, tmp_path, scope=["a.c", "b.c"], scope_floor=True,
        )
        # Floor picks the first gap per file; the pin IS b.c's slot.
        assert {g["name"] for g in kept} == {"target", "high"}

    def test_unmatched_pin_warns_but_never_fails(self, caplog):
        from core.audit.gaps import hoist_pins
        with caplog.at_level("WARNING"):
            out = hoist_pins(self._gaps(), ["z.c:ghost"])
        assert [g["name"] for g in out] == ["high", "mid", "low", "target"]
        assert any("matched no gap" in r.message for r in caplog.records)

    def test_no_pins_is_identity(self):
        from core.audit.gaps import hoist_pins
        gaps = self._gaps()
        assert hoist_pins(gaps, None) is gaps
        assert hoist_pins(gaps, []) is gaps
