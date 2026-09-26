"""Tests for the pipeline-agnostic resume substrate (core.run.resume).

The /audit binding keeps its own suite (core/audit/tests/
test_resume_substrate.py and friends); these tests pin the substrate
seams the bindings parameterise — filenames, completion artifacts,
hint threading, whole-file drift evidence, and the max-of-evidence
spend rule.
"""

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.run.resume import (
    EXHAUSTED_BUDGET_EPSILON_USD,
    _MAX_SPEND_EVIDENCE_USD,
    SpanDriftRecord,
    hash_whole_file,
    load_run_config,
    max_of_evidence,
    persist_spend_floor,
    remaining_budget_usd,
    resume_ineligibility,
    save_run_config,
    spans_drift,
    spend_floor_usd,
)

_CONFIG = "example-run-config.json"


class TestRunConfigPin(unittest.TestCase):

    def test_round_trip_honours_filename(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            cfg = {"version": 1, "models": ["a", "b"]}
            path = save_run_config(out, cfg, filename=_CONFIG)
            self.assertEqual(path.name, _CONFIG)
            self.assertEqual(load_run_config(out, filename=_CONFIG), cfg)
            # A different filename is a different pin.
            self.assertIsNone(load_run_config(out, filename="other.json"))

    def test_corrupt_and_non_dict_return_none(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            (out / _CONFIG).write_text("{nope")
            self.assertIsNone(load_run_config(out, filename=_CONFIG))
            (out / _CONFIG).write_text("[1, 2]")
            self.assertIsNone(load_run_config(out, filename=_CONFIG))

    def test_oversize_returns_none(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            cfg = {"version": 1, "padding": "x" * 4096}
            (out / _CONFIG).write_text(json.dumps(cfg))
            self.assertIsNone(
                load_run_config(out, filename=_CONFIG, max_bytes=64),
            )


class TestEligibility(unittest.TestCase):

    _ARTIFACTS = ("alpha-result.json", "beta-result.json")

    def _check(self, out, **kw):
        kw.setdefault("completion_artifacts", self._ARTIFACTS)
        return resume_ineligibility(out, **kw)

    def test_not_a_run_dir(self):
        with TemporaryDirectory() as d:
            msg = self._check(Path(d))
            self.assertIn("not a run directory", msg)

    def test_completed_with_any_artifact_is_final(self):
        from core.run import complete_run, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            # ANY completion artifact makes the completion genuine.
            (out / "beta-result.json").write_text("{}")
            complete_run(out)
            msg = self._check(out, completed_hint="Start over instead.")
            self.assertIn("never resumed", msg)
            self.assertIn("Start over instead.", msg)

    def test_contradicted_completion_names_artifacts_and_example(self):
        from core.run import complete_run, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            complete_run(out)
            msg = self._check(
                out, contradiction_example=" (e.g. a foreign finaliser)",
            )
            self.assertIn("alpha-result.json / beta-result.json", msg)
            self.assertIn("(e.g. a foreign finaliser)", msg)
            self.assertIn("--reopen", msg)

    def test_reopen_flips_contradicted_completion(self):
        from core.json import load_json
        from core.run import RUN_METADATA_FILE, complete_run, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            complete_run(out)
            # Hermetic worker record: whether start_run stamped a
            # worker depends on the launch shape of the TEST process
            # (session-bound runs record the live parent shell). Model
            # the motivating incident — the real worker was killed —
            # so the reopen decision under test is the dead-worker
            # path in every environment.
            self._set_worker(out, 2 ** 22 + 12345,  # beyond pid_max
                             tool_pid_start=None)
            self.assertIsNone(self._check(out, reopen=True))
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "interrupted")

    def test_reopen_never_unseals_a_genuine_completion(self):
        from core.run import complete_run, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            (out / "alpha-result.json").write_text("{}")
            complete_run(out)
            msg = self._check(out, reopen=True)
            self.assertIn("never resumed", msg)

    def _set_worker(self, out, tool_pid, tool_pid_start=...):
        """Rewrite ONLY the worker record (status untouched).

        Same stamp semantics as :meth:`_mark_running`:
        ``tool_pid_start=...`` (default) records the pid's real
        starttime (a coherent, live-if-the-pid-is identity); ``None``
        strips the stamp (legacy bare-pid record); any other value
        models the recycled-pid mismatch.
        """
        from core.json import load_json, save_json
        from core.project.sessions import proc_starttime
        from core.run import RUN_METADATA_FILE
        meta_path = Path(out) / RUN_METADATA_FILE
        meta = load_json(meta_path)
        meta["tool_pid"] = tool_pid
        if tool_pid_start is ...:
            tool_pid_start = (proc_starttime(tool_pid)
                              if isinstance(tool_pid, int)
                              and tool_pid > 0 else None)
        if tool_pid_start is None:
            meta.pop("tool_pid_start", None)
        else:
            meta["tool_pid_start"] = tool_pid_start
        save_json(meta_path, meta)

    def _contradicted_completed_run(self, d):
        """A run whose 'completed' status is contradicted (no
        completion artifact) — the shape --reopen exists for."""
        from core.run import complete_run, start_run
        out = Path(d) / "run"
        start_run(out, "example")
        complete_run(out)
        return out

    def test_reopen_with_live_worker_refused(self):
        """The double-spend shape: a step that did not own the run
        stamped it 'completed' while the recorded worker was still
        mid-flight (complete_run never clears the worker stamp).
        Reopening then would start a second segment against the
        in-flight run — refuse loudly, naming the pid, and mutate
        NOTHING (the status stays 'completed', no reopen row)."""
        import subprocess

        from core.json import load_json
        from core.run import RUN_METADATA_FILE
        with TemporaryDirectory() as d:
            out = self._contradicted_completed_run(d)
            worker = subprocess.Popen(["sleep", "300"])
            try:
                self._set_worker(out, worker.pid)  # live + coherent
                msg = self._check(out, reopen=True)
                self.assertIsNotNone(msg)
                self.assertIn("still alive", msg)
                self.assertIn(str(worker.pid), msg)
                self.assertIn("double-drive", msg)
                meta = load_json(out / RUN_METADATA_FILE)
                self.assertEqual(meta["status"], "completed")
                self.assertNotIn("reopens", meta.get("extra") or {})
            finally:
                worker.kill()
                worker.wait()

    def test_reopen_with_dead_worker_proceeds(self):
        from core.json import load_json
        from core.run import RUN_METADATA_FILE
        with TemporaryDirectory() as d:
            out = self._contradicted_completed_run(d)
            self._set_worker(out, 2 ** 22 + 12345,  # beyond pid_max
                             tool_pid_start=None)
            self.assertIsNone(self._check(out, reopen=True))
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "interrupted")

    def test_reopen_with_recycled_worker_proceeds(self):
        """Pid alive but identity mismatched (a different process
        recycled the pid): the original worker is dead — reopen
        proceeds. Same identity semantics as the running-status
        guard."""
        from unittest import mock

        from core.json import load_json
        from core.project import sessions
        from core.run import RUN_METADATA_FILE
        with TemporaryDirectory() as d:
            out = self._contradicted_completed_run(d)
            self._set_worker(out, os.getpid(), tool_pid_start="1")
            with mock.patch.object(sessions, "proc_starttime",
                                   lambda pid: "777"):
                self.assertIsNone(self._check(out, reopen=True))
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "interrupted")

    def test_reopen_with_legacy_bare_pid_live_refused(self):
        """Legacy record (no start-time stamp) with the pid alive:
        the running-status guard refuses these (identity unverified,
        err toward not double-driving) — the reopen path keeps the
        same behaviour."""
        with TemporaryDirectory() as d:
            out = self._contradicted_completed_run(d)
            self._set_worker(out, os.getpid(), tool_pid_start=None)
            msg = self._check(out, reopen=True)
            self.assertIn("still alive", msg)
            self.assertIn("legacy record", msg)

    def test_interrupted_eligible(self):
        from core.run import interrupt_run, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            interrupt_run(out, "supervisor stop")
            self.assertIsNone(self._check(out))

    def _mark_running(self, out, tool_pid, tool_pid_start=...):
        """Flip a started run to running with a chosen worker record.

        ``tool_pid_start=...`` (default) keeps the stamp COHERENT with
        the substituted pid — a mismatching stamp is the recycled-pid
        shape, which is deliberately not live. Pass an explicit value
        (or None to strip) to model the other record shapes.
        """
        from core.json import load_json, save_json
        from core.project.sessions import proc_starttime
        from core.run import RUN_METADATA_FILE
        meta_path = Path(out) / RUN_METADATA_FILE
        meta = load_json(meta_path)
        meta["status"] = "running"
        meta["tool_pid"] = tool_pid
        if tool_pid_start is ...:
            tool_pid_start = (proc_starttime(tool_pid)
                              if isinstance(tool_pid, int)
                              and tool_pid > 0 else None)
        if tool_pid_start is None:
            meta.pop("tool_pid_start", None)
        else:
            meta["tool_pid_start"] = tool_pid_start
        save_json(meta_path, meta)

    def test_running_with_live_worker_refused(self):
        from core.run import start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            self._mark_running(out, os.getpid())  # demonstrably alive
            msg = self._check(out)
            self.assertIn("still in flight", msg)
            self.assertIn(str(os.getpid()), msg)

    def test_running_with_init_worker_eligible(self):
        """The detached-launch incident shape: setsid/nohup reparented
        the orchestrator to init before start_run, so the record
        carried tool_pid=1 — and PID 1 is always alive, so this
        refusal was PERMANENT until the metadata was hand-edited.
        pid<=1 is never live evidence: the resume proceeds, with the
        decision noted."""
        from unittest import mock

        from core.run import start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            self._mark_running(out, 1, tool_pid_start=None)
            with mock.patch("core.run.metadata._PID1_NOTE_EMITTED",
                            False), \
                    self.assertLogs("core.run.metadata",
                                    level="WARNING") as cm:
                self.assertIsNone(self._check(out))
            self.assertTrue(any(
                "never a liveness credential" in line
                for line in cm.output))

    def test_running_with_recycled_worker_eligible(self):
        """Recycled pid: a live process holds the recorded pid, but
        its /proc starttime differs from the stamp — the original
        worker is dead, the run is not in flight."""
        from unittest import mock

        from core.project import sessions
        from core.run import start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            self._mark_running(out, os.getpid(), tool_pid_start="1")
            with mock.patch.object(sessions, "proc_starttime",
                                   lambda pid: "777"):
                self.assertIsNone(self._check(out))

    def test_running_with_legacy_bare_pid_record_refused(self):
        """Legacy record (no start-time stamp), worker alive: the old
        behaviour is preserved — refuse, naming the unverified
        identity."""
        from core.run import start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            self._mark_running(out, os.getpid(), tool_pid_start=None)
            msg = self._check(out)
            self.assertIn("still in flight", msg)
            self.assertIn("legacy record", msg)

    def test_running_with_dead_worker_eligible(self):
        from core.run import start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "example")
            self._mark_running(out, 2 ** 22 + 12345,  # beyond pid_max
                               tool_pid_start=None)
            self.assertIsNone(self._check(out))

    def test_understand_caller_shape_gets_identity_semantics(self):
        """The substrate serves every pipeline: invoked exactly the
        way the /understand resume path calls it (its completion
        artifacts and hint), the incident-shape record still resumes
        and the true-in-flight record still refuses with the evidence
        named — the identity semantics are the chokepoint's, not the
        audit wrapper's."""
        from unittest import mock

        from core.run import start_run
        kwargs = dict(
            completion_artifacts=("map-result.json", "hunt-result.json",
                                  "trace-result.json"),
            completed_hint="Start a new /understand run instead.",
            contradiction_example=(
                " (e.g. another command's lifecycle complete on this "
                "dir)"
            ),
        )
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "understand")
            self._mark_running(out, 1, tool_pid_start=None)
            with mock.patch("core.run.metadata._PID1_NOTE_EMITTED",
                            False):
                self.assertIsNone(resume_ineligibility(out, **kwargs))
            self._mark_running(out, os.getpid())
            msg = resume_ineligibility(out, **kwargs)
            self.assertIn("still in flight", msg)
            self.assertIn(str(os.getpid()), msg)


class TestWholeFileHash(unittest.TestCase):

    def test_stable_and_change_sensitive(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "x.c"
            f.write_text("int a;\n")
            h1 = hash_whole_file(f)
            self.assertEqual(len(h1), 12)
            self.assertEqual(hash_whole_file(f), h1)
            f.write_text("int b;\n")
            self.assertNotEqual(hash_whole_file(f), h1)

    def test_missing_file_hashes_empty(self):
        with TemporaryDirectory() as d:
            self.assertEqual(hash_whole_file(Path(d) / "gone.c"), "")


class TestSpansDrift(unittest.TestCase):

    def test_unchanged_whole_file_no_drift(self):
        with TemporaryDirectory() as d:
            target = Path(d)
            (target / "a.c").write_text("void f(void) {}\n")
            stored = hash_whole_file(target / "a.c")
            drifted, checked = spans_drift(target, [
                SpanDriftRecord(file="a.c", label="m1", stored_hash=stored),
            ])
            self.assertEqual(checked, 1)
            self.assertEqual(drifted, [])

    def test_changed_whole_file_drifts(self):
        with TemporaryDirectory() as d:
            target = Path(d)
            (target / "a.c").write_text("void f(void) {}\n")
            stored = hash_whole_file(target / "a.c")
            (target / "a.c").write_text("void f(int x) {}\n")
            drifted, checked = spans_drift(target, [
                SpanDriftRecord(file="a.c", label="m1", stored_hash=stored),
            ])
            self.assertEqual(checked, 1)
            self.assertEqual(len(drifted), 1)
            self.assertEqual(drifted[0].file, "a.c")
            self.assertEqual(drifted[0].label, "m1")
            self.assertEqual(drifted[0].stored_hash, stored)

    def test_deleted_file_counts_as_drift(self):
        with TemporaryDirectory() as d:
            target = Path(d)
            drifted, checked = spans_drift(target, [
                SpanDriftRecord(file="gone.c", label="m1",
                                stored_hash="abc123"),
            ])
            self.assertEqual(checked, 1)
            self.assertEqual(drifted[0].current_hash, "")

    def test_span_records_use_span_hashing(self):
        from core.staleness import hash_span
        with TemporaryDirectory() as d:
            target = Path(d)
            (target / "a.c").write_text("int a;\nint b;\nint c;\n")
            stored = hash_span(target / "a.c", 2, 2)
            records = [SpanDriftRecord(
                file="a.c", label="f", stored_hash=stored,
                line_start=2, line_end=2,
            )]
            drifted, checked = spans_drift(target, records)
            self.assertEqual((len(drifted), checked), (0, 1))
            (target / "a.c").write_text("int a;\nint B;\nint c;\n")
            drifted, checked = spans_drift(target, records)
            self.assertEqual((len(drifted), checked), (1, 1))

    def test_common_prefix_comparison(self):
        """Stored and current hashes recorded at different prefix
        lengths must still compare equal on the common prefix."""
        with TemporaryDirectory() as d:
            target = Path(d)
            (target / "a.c").write_text("int a;\n")
            stored = hash_whole_file(target / "a.c")[:8]
            drifted, checked = spans_drift(target, [
                SpanDriftRecord(file="a.c", label="m", stored_hash=stored),
            ])
            self.assertEqual((len(drifted), checked), (0, 1))

    def test_traversal_paths_rejected_as_drift(self):
        with TemporaryDirectory() as d:
            target = Path(d) / "repo"
            target.mkdir()
            outside = Path(d) / "secret.c"
            outside.write_text("int s;\n")
            stored = hash_whole_file(outside)
            drifted, checked = spans_drift(target, [
                SpanDriftRecord(file="../secret.c", label="m",
                                stored_hash=stored),
            ])
            # Escaping paths never resolve — they read as drift, not
            # as a read outside the target.
            self.assertEqual(checked, 1)
            self.assertEqual(drifted[0].current_hash, "")

    def test_unverifiable_records_skipped(self):
        with TemporaryDirectory() as d:
            drifted, checked = spans_drift(Path(d), [
                SpanDriftRecord(file="a.c", label="m", stored_hash=""),
            ])
            self.assertEqual((drifted, checked), ([], 0))


class TestSpendEvidence(unittest.TestCase):

    def test_max_of_evidence_first_maximal_wins(self):
        booked, note = max_of_evidence([
            (2.0, "ledger"), (2.0, "journal"), (1.0, "floor"),
        ])
        self.assertEqual((booked, note), (2.0, "ledger"))

    def test_max_of_evidence_takes_the_max(self):
        booked, note = max_of_evidence([
            (1.0, "ledger"), (5.0, "floor"),
        ])
        self.assertEqual((booked, note), (5.0, "floor"))

    def test_max_of_evidence_clamps_hostile_values(self):
        booked, note = max_of_evidence([
            (float("inf"), "planted"), (3.0, "real"),
        ])
        self.assertEqual(booked, _MAX_SPEND_EVIDENCE_USD)
        self.assertEqual(note, "planted")
        booked, note = max_of_evidence([
            (float("nan"), "planted"), (3.0, "real"),
        ])
        self.assertEqual((booked, note), (3.0, "real"))

    def test_max_of_evidence_empty_books_zero(self):
        self.assertEqual(max_of_evidence([]), (0.0, ""))

    def test_max_of_evidence_noteless_max_keeps_its_value(self):
        # A maximal source carrying an empty note must keep the
        # booked VALUE — a later, smaller source's note used to
        # rebind both, under-booking the run's spend.
        booked, note = max_of_evidence([(5.0, ""), (3.0, "b")])
        self.assertEqual(booked, 5.0)

    def test_max_of_evidence_equal_value_backfills_empty_note(self):
        # Same value, later note: the note (display-only) may be
        # backfilled, the booked figure is unchanged.
        booked, note = max_of_evidence([(0.0, ""), (0.0, "b")])
        self.assertEqual((booked, note), (0.0, "b"))

    def test_spend_floor_monotonic(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            persist_spend_floor(out, 4.0, segment=1)
            persist_spend_floor(out, 2.0, segment=2)  # never lowers
            self.assertEqual(spend_floor_usd(out), 4.0)
            persist_spend_floor(out, 6.5)
            self.assertEqual(spend_floor_usd(out), 6.5)

    def test_remaining_budget(self):
        self.assertIsNone(remaining_budget_usd(None, 100.0))
        self.assertEqual(remaining_budget_usd(10.0, 4.0), 6.0)
        self.assertEqual(
            remaining_budget_usd(10.0, 12.0),
            EXHAUSTED_BUDGET_EPSILON_USD,
        )


if __name__ == "__main__":
    unittest.main()
