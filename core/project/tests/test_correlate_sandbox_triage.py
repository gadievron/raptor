"""Tests for correlate_sandbox_triage — campaign-level aggregation of
sandbox denial triage across runs."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.correlate import correlate_sandbox_triage


def _write_run(base: Path, name: str, triage: dict, *,
               target: str = "/src/app",
               ts: str = "2026-09-20T00:00:00") -> Path:
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "sandbox-summary.json").write_text(json.dumps({"triage": triage}))
    (d / ".raptor-run.json").write_text(json.dumps({
        "target_path": target,
        "started_at": ts,
        "command": "agentic",
    }))
    return d


def _triage(escape=0, network=0, udp=0, fs=0, routine=0,
            severity="routine"):
    t = {}
    cats = [
        ("escape_primitives", escape, ["ptrace"]),
        ("network_probing", network, ["curl h1"]),
        ("udp_egress", udp, ["dns query"]),
        ("filesystem_escape", fs, ["/etc/passwd"]),
        ("routine", routine, ["write:/tmp/x"]),
    ]
    for cat, count, ex in cats:
        t[cat] = {"count": count, "examples": ex[:count] if count else []}
    t["severity"] = severity
    return t


class TestCorrelateNoData(unittest.TestCase):
    def test_returns_none_with_empty_list(self):
        self.assertIsNone(correlate_sandbox_triage([]))

    def test_returns_none_when_no_triage_key(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp) / "run1"
            d.mkdir()
            (d / "sandbox-summary.json").write_text("{}")
            (d / ".raptor-run.json").write_text(json.dumps({
                "target_path": "/x", "started_at": "t", "command": "scan",
            }))
            self.assertIsNone(correlate_sandbox_triage([d]))

    def test_returns_none_when_no_summary_file(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp) / "run1"
            d.mkdir()
            self.assertIsNone(correlate_sandbox_triage([d]))


class TestSingleRun(unittest.TestCase):
    def test_single_run_critical(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            d = _write_run(base, "r1",
                           _triage(escape=2, severity="critical"))
            result = correlate_sandbox_triage([d])
            self.assertIsNotNone(result)
            self.assertEqual(result["campaign_severity"], "critical")
            t = result["targets"]["/src/app"]
            self.assertEqual(t["runs_with_triage"], 1)
            self.assertEqual(t["signatures"]["escape_primitives"]["runs_seen"], 1)
            self.assertEqual(
                t["signatures"]["escape_primitives"]["trend"], "new")

    def test_single_run_routine(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            d = _write_run(base, "r1",
                           _triage(routine=3, severity="routine"))
            result = correlate_sandbox_triage([d])
            self.assertEqual(result["campaign_severity"], "routine")


class TestMultiRun(unittest.TestCase):
    def test_persistence_and_trend(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            dirs = [
                _write_run(base, f"r{i}",
                           _triage(escape=1, severity="critical"),
                           ts=f"2026-09-{20+i:02d}T00:00:00")
                for i in range(5)
            ]
            result = correlate_sandbox_triage(dirs)
            t = result["targets"]["/src/app"]
            sig = t["signatures"]["escape_primitives"]
            self.assertEqual(sig["runs_seen"], 5)
            self.assertEqual(sig["persistence"], 1.0)
            self.assertEqual(sig["trend"], "stable")

    def test_resolved_trend(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            dirs = [
                _write_run(base, "r0",
                           _triage(escape=1, severity="critical"),
                           ts="2026-09-20T00:00:00"),
                _write_run(base, "r1",
                           _triage(escape=1, severity="critical"),
                           ts="2026-09-21T00:00:00"),
                _write_run(base, "r2",
                           _triage(severity="routine"),
                           ts="2026-09-22T00:00:00"),
                _write_run(base, "r3",
                           _triage(severity="routine"),
                           ts="2026-09-23T00:00:00"),
                _write_run(base, "r4",
                           _triage(severity="routine"),
                           ts="2026-09-24T00:00:00"),
            ]
            result = correlate_sandbox_triage(dirs)
            sig = result["targets"]["/src/app"]["signatures"]["escape_primitives"]
            self.assertEqual(sig["trend"], "resolved")
            self.assertEqual(sig["runs_seen"], 2)

    def test_new_trend(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            dirs = [
                _write_run(base, "r0",
                           _triage(severity="routine"),
                           ts="2026-09-20T00:00:00"),
                _write_run(base, "r1",
                           _triage(severity="routine"),
                           ts="2026-09-21T00:00:00"),
                _write_run(base, "r2",
                           _triage(udp=3, severity="elevated"),
                           ts="2026-09-22T00:00:00"),
                _write_run(base, "r3",
                           _triage(udp=2, severity="elevated"),
                           ts="2026-09-23T00:00:00"),
            ]
            result = correlate_sandbox_triage(dirs)
            sig = result["targets"]["/src/app"]["signatures"]["udp_egress"]
            self.assertEqual(sig["trend"], "new")


class TestPerTarget(unittest.TestCase):
    def test_separate_targets(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            d1 = _write_run(base, "r1",
                            _triage(escape=1, severity="critical"),
                            target="/src/app-a")
            d2 = _write_run(base, "r2",
                            _triage(severity="routine"),
                            target="/src/app-b")
            result = correlate_sandbox_triage([d1, d2])
            self.assertIn("/src/app-a", result["targets"])
            self.assertIn("/src/app-b", result["targets"])
            self.assertEqual(
                result["targets"]["/src/app-a"]["campaign_severity"], "critical")
            self.assertEqual(
                result["targets"]["/src/app-b"]["campaign_severity"], "routine")
            self.assertEqual(result["campaign_severity"], "critical")


class TestPersistenceUpgrade(unittest.TestCase):
    def test_no_upgrade_below_4_runs(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            dirs = [
                _write_run(base, f"r{i}",
                           _triage(network=5, severity="routine"),
                           ts=f"2026-09-{20+i:02d}T00:00:00")
                for i in range(3)
            ]
            result = correlate_sandbox_triage(dirs)
            self.assertEqual(
                result["targets"]["/src/app"]["campaign_severity"], "routine")

    def test_upgrade_at_4_runs(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            dirs = [
                _write_run(base, f"r{i}",
                           _triage(network=5, severity="routine"),
                           ts=f"2026-09-{20+i:02d}T00:00:00")
                for i in range(4)
            ]
            result = correlate_sandbox_triage(dirs)
            # network_probing present in all 4 runs → persistence 1.0 > 0.5
            # but network_probing count=5 (≤5 threshold) → per-run severity
            # is "routine". Persistence upgrade: routine → elevated.
            self.assertEqual(
                result["targets"]["/src/app"]["campaign_severity"], "elevated")


class TestSeverityHistory(unittest.TestCase):
    def test_capped_at_50(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            dirs = [
                _write_run(base, f"r{i:03d}",
                           _triage(severity="routine"),
                           ts=f"2026-{(i // 28) + 1:02d}-{(i % 28) + 1:02d}T00:00:00")
                for i in range(60)
            ]
            result = correlate_sandbox_triage(dirs)
            history = result["targets"]["/src/app"]["severity_history"]
            self.assertLessEqual(len(history), 50)
            self.assertEqual(history[-1]["run"], "r059")


if __name__ == "__main__":
    unittest.main()
