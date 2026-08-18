"""Tests for the same-run resume substrate (core.audit.resume)."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.audit.resume import (
    EXHAUSTED_BUDGET_EPSILON_USD,
    RUN_CONFIG_FILENAME,
    append_resume_markers,
    booked_spend_usd,
    compute_drift,
    journal_spend_usd,
    load_prior_cost_breakdown,
    load_run_config,
    remaining_budget_usd,
    resume_ineligibility,
    save_run_config,
)
from core.coverage.journal import ReviewJournalEntry, append_entry, now_iso


def _journal(out_dir: Path, file: str, function: str, *,
             verdict: str = "clean", source_hash: str = "",
             line_start: int = 1, line_end: int | None = None,
             cost_usd: float | None = None) -> None:
    append_entry(out_dir, ReviewJournalEntry(
        ts=now_iso(),
        run_id=out_dir.name,
        file=file,
        function=function,
        verdict=verdict,
        source_hash=source_hash,
        line_start=line_start,
        line_end=line_end,
        cost_usd=cost_usd,
    ))


class TestRunConfigPersistence(unittest.TestCase):

    def test_round_trip(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            cfg = {"version": 1, "max_cost_usd": 12.5, "scope": ["src/"]}
            path = save_run_config(out, cfg)
            self.assertEqual(path.name, RUN_CONFIG_FILENAME)
            self.assertEqual(load_run_config(out), cfg)

    def test_missing_returns_none(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(load_run_config(Path(d)))

    def test_corrupt_returns_none(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            (out / RUN_CONFIG_FILENAME).write_text("{nope")
            self.assertIsNone(load_run_config(out))


class TestEligibility(unittest.TestCase):

    def test_not_a_run_dir(self):
        with TemporaryDirectory() as d:
            msg = resume_ineligibility(Path(d))
            self.assertIsNotNone(msg)
            self.assertIn("not a run directory", msg)

    def test_completed_refused_with_new_run_hint(self):
        from core.run import complete_run, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "audit")
            complete_run(out)
            msg = resume_ineligibility(out)
            self.assertIsNotNone(msg)
            self.assertIn("completed", msg)
            self.assertIn("verdict reuse", msg)

    def test_interrupted_eligible(self):
        from core.run import interrupt_run, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "audit")
            interrupt_run(out, "supervisor stop")
            self.assertIsNone(resume_ineligibility(out))

    def test_running_with_live_worker_refused(self):
        import os

        from core.json import load_json, save_json
        from core.run import RUN_METADATA_FILE, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "audit")
            meta_path = out / RUN_METADATA_FILE
            meta = load_json(meta_path)
            meta["status"] = "running"
            meta["tool_pid"] = os.getpid()  # demonstrably alive
            save_json(meta_path, meta)
            msg = resume_ineligibility(out)
            self.assertIsNotNone(msg)
            self.assertIn("still in flight", msg)

    def test_running_with_dead_worker_eligible(self):
        """SIGKILLed run: status stuck at running, worker gone."""
        from core.json import load_json, save_json
        from core.run import RUN_METADATA_FILE, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "audit")
            meta_path = out / RUN_METADATA_FILE
            meta = load_json(meta_path)
            meta["status"] = "running"
            meta["tool_pid"] = 2 ** 22 + 12345  # beyond pid_max default
            save_json(meta_path, meta)
            self.assertIsNone(resume_ineligibility(out))


class TestDriftGate(unittest.TestCase):

    def _target_with_file(self, root: Path, body: str) -> Path:
        target = root / "target"
        target.mkdir()
        (target / "a.c").write_text(body)
        return target

    def _hash_span(self, path: Path, start: int, end: int) -> str:
        from core.staleness import hash_spans
        return hash_spans(path, [(start, end)])[0]

    def test_no_drift_when_source_unchanged(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            target = self._target_with_file(root, "int f() {\n  return 1;\n}\n")
            out = root / "run"
            out.mkdir()
            h = self._hash_span(target / "a.c", 1, 3)
            _journal(out, "a.c", "f", source_hash=h, line_start=1, line_end=3)
            drifted, checked = compute_drift(out, target)
            self.assertEqual(checked, 1)
            self.assertEqual(drifted, [])

    def test_drift_detected_on_source_change(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            target = self._target_with_file(root, "int f() {\n  return 1;\n}\n")
            out = root / "run"
            out.mkdir()
            h = self._hash_span(target / "a.c", 1, 3)
            _journal(out, "a.c", "f", source_hash=h, line_start=1, line_end=3)
            (target / "a.c").write_text("int f() {\n  return 2;\n}\n")
            drifted, checked = compute_drift(out, target)
            self.assertEqual(checked, 1)
            self.assertEqual(len(drifted), 1)
            self.assertEqual(drifted[0].file, "a.c")
            self.assertEqual(drifted[0].function, "f")
            self.assertEqual(drifted[0].stored_hash, h)
            self.assertNotEqual(drifted[0].current_hash, h)

    def test_deleted_file_counts_as_drift(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            target = self._target_with_file(root, "int f() {\n  return 1;\n}\n")
            out = root / "run"
            out.mkdir()
            h = self._hash_span(target / "a.c", 1, 3)
            _journal(out, "a.c", "f", source_hash=h, line_start=1, line_end=3)
            (target / "a.c").unlink()
            drifted, _ = compute_drift(out, target)
            self.assertEqual(len(drifted), 1)
            self.assertEqual(drifted[0].current_hash, "")

    def test_error_and_hashless_entries_skipped(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            target = self._target_with_file(root, "int f() {\n  return 1;\n}\n")
            out = root / "run"
            out.mkdir()
            _journal(out, "a.c", "err", verdict="error",
                     source_hash="deadbeef", line_start=1, line_end=3)
            _journal(out, "a.c", "nohash", source_hash="", line_start=1)
            drifted, checked = compute_drift(out, target)
            self.assertEqual(checked, 0)
            self.assertEqual(drifted, [])

    def test_traversal_path_rejected_not_hashed(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            target = self._target_with_file(root, "x\n")
            out = root / "run"
            out.mkdir()
            _journal(out, "../secret.c", "f", source_hash="abc",
                     line_start=1, line_end=1)
            drifted, checked = compute_drift(out, target)
            # Unresolvable path → counted, drifted (no current source).
            self.assertEqual(checked, 1)
            self.assertEqual(len(drifted), 1)
            self.assertEqual(drifted[0].current_hash, "")


class TestBudgetMath(unittest.TestCase):

    def test_booked_spend_prefers_reconciled_total(self):
        breakdown = {
            "phases": {"review": {"cost_usd": 2.0}},
            "totals": {
                "cost_usd": 2.0,
                "failed_attempts_cost_usd": 0.5,
                "total_spend_usd": 3.25,
            },
        }
        self.assertEqual(booked_spend_usd(breakdown), 3.25)

    def test_booked_spend_falls_back_to_tracked(self):
        breakdown = {
            "totals": {"cost_usd": 2.0, "failed_attempts_cost_usd": 0.5},
        }
        self.assertEqual(booked_spend_usd(breakdown), 2.5)

    def test_booked_spend_missing_ledger_is_zero(self):
        self.assertEqual(booked_spend_usd(None), 0.0)

    def test_journal_spend_floor(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            _journal(out, "a.c", "f", cost_usd=0.4)
            _journal(out, "a.c", "g", cost_usd=0.35)
            _journal(out, "a.c", "h")  # no cost recorded
            self.assertAlmostEqual(journal_spend_usd(out), 0.75)

    def test_remaining_budget_math(self):
        self.assertIsNone(remaining_budget_usd(None, 5.0))
        self.assertAlmostEqual(remaining_budget_usd(10.0, 3.25), 6.75)
        self.assertEqual(
            remaining_budget_usd(10.0, 10.0), EXHAUSTED_BUDGET_EPSILON_USD,
        )
        self.assertEqual(
            remaining_budget_usd(10.0, 12.0), EXHAUSTED_BUDGET_EPSILON_USD,
        )

    def test_load_prior_cost_breakdown(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            self.assertIsNone(load_prior_cost_breakdown(out))
            (out / "cost-breakdown.json").write_text(
                json.dumps({"totals": {"total_spend_usd": 1.0}}),
            )
            self.assertEqual(
                booked_spend_usd(load_prior_cost_breakdown(out)), 1.0,
            )


class TestResumeMarkers(unittest.TestCase):

    def test_markers_appended_to_both_ledgers(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            # Pre-existing telemetry rows must survive (append, not
            # truncate).
            (out / "llm-telemetry.jsonl").write_text(
                json.dumps({"call_class": "review", "cost_usd": 0.1}) + "\n",
            )
            append_resume_markers(out, segment=2)

            telemetry = [
                json.loads(line)
                for line in (out / "llm-telemetry.jsonl")
                .read_text().splitlines()
            ]
            self.assertEqual(len(telemetry), 2)
            self.assertEqual(telemetry[1]["event"], "resume_marker")
            self.assertEqual(telemetry[1]["segment"], 2)

            from core.audit.record import load_audit_log
            log = load_audit_log(out)
            markers = [e for e in log if e.get("action") == "resume"]
            self.assertEqual(len(markers), 1)
            self.assertEqual(markers[0]["segment"], 2)


if __name__ == "__main__":
    unittest.main()


class TestSpendFloor(unittest.TestCase):
    """Incremental spend floor: a hard-killed segment's spend must be
    bookable by the next segment even though cost-breakdown.json was
    never written."""

    def test_round_trip(self):
        from core.audit.resume import persist_spend_floor, spend_floor_usd
        with TemporaryDirectory() as d:
            out = Path(d)
            self.assertEqual(spend_floor_usd(out), 0.0)
            persist_spend_floor(out, 1.25, segment=1)
            self.assertAlmostEqual(spend_floor_usd(out), 1.25)

    def test_monotonic_never_lowers(self):
        from core.audit.resume import persist_spend_floor, spend_floor_usd
        with TemporaryDirectory() as d:
            out = Path(d)
            persist_spend_floor(out, 3.0)
            persist_spend_floor(out, 1.0)
            self.assertAlmostEqual(spend_floor_usd(out), 3.0)

    def test_corrupt_reads_zero(self):
        from core.audit.resume import SPEND_FLOOR_FILENAME, spend_floor_usd
        with TemporaryDirectory() as d:
            out = Path(d)
            (out / SPEND_FLOOR_FILENAME).write_text("{not json")
            self.assertEqual(spend_floor_usd(out), 0.0)

    def test_missing_out_dir_is_noop(self):
        from core.audit.resume import persist_spend_floor
        persist_spend_floor(Path("/nonexistent/dir/xyz"), 5.0)

    def test_budget_poll_persists_floor(self):
        """_check_budget keeps the floor fresh: a segment killed
        between reconciliations still has its spend on disk."""
        import time as _time

        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _check_budget,
        )
        from core.audit.resume import spend_floor_usd
        with TemporaryDirectory() as d:
            out = Path(d)
            config = OrchestratorConfig(target_path=out, out_dir=out)
            result = OrchestratorResult()
            result.total_cost_usd = 2.5
            self.assertFalse(
                _check_budget(config, _time.monotonic(), result))
            self.assertAlmostEqual(spend_floor_usd(out), 2.5)

    def test_budget_poll_includes_client_ledgers(self):
        import time as _time

        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _check_budget,
        )
        from core.audit.resume import spend_floor_usd

        class _Client:
            total_cost = 1.0
            provider_spend_usd = 4.0

            @staticmethod
            def is_budget_exhausted():
                return False

        with TemporaryDirectory() as d:
            out = Path(d)
            config = OrchestratorConfig(target_path=out, out_dir=out)
            config.llm_budget_client = _Client()
            result = OrchestratorResult()
            result.total_cost_usd = 0.5
            _check_budget(config, _time.monotonic(), result)
            # max(outcome ledger, client ledger, provider ledger)
            self.assertAlmostEqual(spend_floor_usd(out), 4.0)

    def test_resume_math_takes_floor_over_stale_ledger(self):
        """The resume budget selection: max(reconciled/journal, floor)
        — the exact rule cmd_resume applies."""
        from core.audit.resume import persist_spend_floor, spend_floor_usd
        with TemporaryDirectory() as d:
            out = Path(d)
            # A stale segment-1 breakdown says $1; the killed segment-2
            # floor recorded $6 before dying.
            (out / "cost-breakdown.json").write_text(
                json.dumps({"totals": {"total_spend_usd": 1.0}}),
            )
            persist_spend_floor(out, 6.0, segment=2)
            booked = booked_spend_usd(load_prior_cost_breakdown(out))
            floor = spend_floor_usd(out)
            self.assertEqual(max(booked, floor), 6.0)
            self.assertEqual(
                remaining_budget_usd(10.0, max(booked, floor)), 4.0,
            )
