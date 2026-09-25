"""Detector-correctness tests for the skip-count budget gate."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_skip_budget.py"


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location("check_skip_budget", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _junit(tmp_path: Path, name: str, skipped: int, tests: int = 50,
           suites: int = 1) -> Path:
    """A junit file shaped like pytest's --junitxml output."""
    body = "".join(
        f'<testsuite name="pytest{i}" errors="0" failures="0" '
        f'skipped="{skipped}" tests="{tests}" time="1.0"></testsuite>'
        for i in range(suites)
    )
    p = tmp_path / name
    p.write_text(f"<?xml version='1.0'?><testsuites>{body}</testsuites>",
                 encoding="utf-8")
    return p


def _baseline(tmp_path: Path, entries: dict) -> Path:
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps(entries), encoding="utf-8")
    return p


def _run(gate, monkeypatch, capsys, argv: list[str]) -> tuple[int, str]:
    monkeypatch.setattr("sys.argv", ["check_skip_budget.py", *argv])
    rc = gate.main()
    return rc, capsys.readouterr().out


class TestJunitParsing:
    def test_counts_skips(self, gate, tmp_path):
        xml = _junit(tmp_path, "a.xml", skipped=7)
        assert gate.count_skips(xml) == 7

    def test_sums_multiple_suites(self, gate, tmp_path):
        xml = _junit(tmp_path, "a.xml", skipped=3, suites=2)
        assert gate.count_skips(xml) == 6

    def test_missing_file_raises(self, gate, tmp_path):
        with pytest.raises(ValueError, match="cannot read"):
            gate.count_skips(tmp_path / "nope.xml")

    def test_xml_without_testsuite_raises(self, gate, tmp_path):
        p = tmp_path / "bad.xml"
        p.write_text("<notjunit/>", encoding="utf-8")
        with pytest.raises(ValueError, match="no <testsuite>"):
            gate.count_skips(p)


class TestGateSemantics:
    def test_growth_over_recorded_count_fails(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=9)
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 1
        assert "skip count changed vs baseline" in out
        assert "9 > recorded 5" in out

    def test_at_recorded_count_passes(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=5)
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, _ = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 0

    def test_shrink_is_silent_on_filtered_runs(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        # A path-filtered run collects a subset — a lower count is
        # expected, not stale headroom.
        xml = _junit(tmp_path, "a.xml", skipped=1)
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 0
        assert "WARN" not in out

    def test_shrink_warns_on_full_runs(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=1)
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base), "--full",
        ])
        assert rc == 0
        assert "WARN" in out
        assert "skip count changed vs baseline" in out

    def test_unrecorded_lane_notices_without_failing(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        # Adoption path: counts are runner-environment facts, seeded
        # from a CI run's own output — an unrecorded lane must report,
        # never block.
        xml = _junit(tmp_path, "a.xml", skipped=4)
        base = _baseline(tmp_path, {})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "new-lane", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 0
        assert "NOTICE" in out
        assert "--write-baseline" in out

    def test_multiple_junit_files_sum(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        a = _junit(tmp_path, "a.xml", skipped=3)
        b = _junit(tmp_path, "b.xml", skipped=4)
        base = _baseline(tmp_path, {"lane-x": {"skips": 6}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(a),
            "--junit-xml", str(b), "--baseline", str(base),
        ])
        assert rc == 1
        assert "7 > recorded 6" in out

    def test_unreadable_junit_is_a_usage_error_not_a_pass(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, _ = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(tmp_path / "gone.xml"),
            "--baseline", str(base),
        ])
        assert rc == 2

    def test_absent_baseline_is_the_adoption_path(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=4)
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(tmp_path / "never-written.json"),
        ])
        assert rc == 0
        assert "NOTICE" in out

    def test_corrupt_baseline_fails_closed_in_read_mode(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        # A present-but-unparseable baseline must be exit 2, not the
        # NOTICE path: falling open would demote EVERY recorded lane
        # to non-enforcing behind one corrupt commit.
        xml = _junit(tmp_path, "a.xml", skipped=4)
        base = tmp_path / "baseline.json"
        base.write_text("{not json", encoding="utf-8")
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 2
        assert "NOTICE" not in out

    def test_misshapen_baseline_fails_closed_in_read_mode(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=4)
        base = tmp_path / "baseline.json"
        base.write_text('["not", "an", "object"]', encoding="utf-8")
        rc, _ = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 2

    def test_non_integer_skips_row_is_an_error_not_a_notice(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=4)
        base = _baseline(tmp_path, {"lane-x": {"skips": "5"}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 2
        assert "NOTICE" not in out


class TestWriteBaseline:
    def test_records_lane_and_preserves_other_rows_and_notes(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=8)
        base = _baseline(tmp_path, {
            "lane-x": {"skips": 5, "note": "reviewed"},
            "lane-y": {"skips": 2, "note": "other lane"},
        })
        rc, _ = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base), "--write-baseline",
        ])
        assert rc == 0
        data = json.loads(base.read_text(encoding="utf-8"))
        assert data["lane-x"] == {"skips": 8, "note": "reviewed"}
        assert data["lane-y"] == {"skips": 2, "note": "other lane"}

    def test_unreadable_baseline_refuses_the_rewrite(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=8)
        base = tmp_path / "baseline.json"
        base.write_text("{not json", encoding="utf-8")
        monkeypatch.setattr("sys.argv", [
            "check_skip_budget.py", "--lane", "lane-x",
            "--junit-xml", str(xml), "--baseline", str(base),
            "--write-baseline",
        ])
        with pytest.raises(SystemExit):
            gate.main()
        assert base.read_text(encoding="utf-8") == "{not json"
