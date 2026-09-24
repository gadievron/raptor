"""Per-run artifact lock: the append/refresh seams must not lose
concurrent updates.

The append seams load a run artifact, mutate it, and save it back;
save_json's per-file atomicity makes an unserialised lost update
clean and invisible. Real interleaves exist (fuzz fold-back vs
trace-parser vs harness on one run dir).
"""

from __future__ import annotations

import hashlib
import os
import threading
import time

import pytest

import packages.binary_analysis.pipeline as pipeline
from core.json import load_json, save_json
from packages.binary_analysis._artifact_lock import run_artifacts_lock


class TestRunArtifactsLock:
    def test_mutual_exclusion_across_threads(self, tmp_path):
        order: list[str] = []
        entered = threading.Event()

        def holder():
            with run_artifacts_lock(tmp_path):
                entered.set()
                time.sleep(0.2)
                order.append("holder-exit")

        def contender():
            entered.wait(timeout=5)
            with run_artifacts_lock(tmp_path):
                order.append("contender-enter")

        threads = [threading.Thread(target=holder),
                   threading.Thread(target=contender)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert order == ["holder-exit", "contender-enter"]

    def test_degrades_when_lock_uncreatable(self, tmp_path):
        missing = tmp_path / "gone"          # lock file uncreatable
        with run_artifacts_lock(missing):
            pass                              # no raise

    def test_planted_symlink_degrades_without_following(self, tmp_path):
        """The run dir is (or was) a sandboxed child's write grant: a
        planted symlink at the predictable lock name must not make
        this process create/flock an attacker-chosen path."""
        victim = tmp_path / "victim"
        (tmp_path / ".binary-artifacts.lock").symlink_to(victim)
        entered = False
        with run_artifacts_lock(tmp_path):
            entered = True
        assert entered
        assert not victim.exists()

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="mkfifo unavailable (non-POSIX)")
    def test_planted_readerless_fifo_degrades_without_blocking(
        self, tmp_path,
    ):
        """A planted reader-less FIFO fails the open fast (ENXIO via
        O_NONBLOCK) instead of wedging every artifact append."""
        os.mkfifo(tmp_path / ".binary-artifacts.lock")
        entered = False
        with run_artifacts_lock(tmp_path):
            entered = True
        assert entered

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="mkfifo unavailable (non-POSIX)")
    def test_planted_fifo_with_reader_refused_by_regularity_check(
        self, tmp_path,
    ):
        fifo = tmp_path / ".binary-artifacts.lock"
        os.mkfifo(fifo)
        reader = os.open(str(fifo), os.O_RDONLY | os.O_NONBLOCK)
        try:
            entered = False
            with run_artifacts_lock(tmp_path):
                entered = True
            assert entered
        finally:
            os.close(reader)


class TestConcurrentFuzzAppend:
    def _seed_run(self, base):
        binary = base / "target.bin"
        binary.write_bytes(b"\x7fELFfake")
        sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        save_json(base / "binary-manifest.json",
                  {"binary_path": str(binary), "binary_sha256": sha})
        save_json(base / "binary-context-map.json", {"target": str(binary)})
        save_json(base / "binary-checklist.json", {"target": str(binary)})
        save_json(base / "binary-evidence.json", {"evidence": []})
        fuzz_dirs = []
        for tag in ("A", "B"):
            fd = base / f"fuzz-{tag}"
            fd.mkdir()
            save_json(fd / "fuzz-summary.json",
                      {"target": str(binary), "fuzzer": f"afl-{tag}",
                       "total_executions": 1, "crashes": 0})
            fuzz_dirs.append(fd)
        return binary, fuzz_dirs

    def test_concurrent_appends_keep_both_evidence_records(
            self, tmp_path, monkeypatch):
        """Two real append_fuzz_evidence_to_run calls race; only the
        scheduling of the load → save window is nudged (both loaders
        are held until both have loaded, or until the lock has kept
        the second one out). No logic is patched."""
        binary, fuzz_dirs = self._seed_run(tmp_path)

        cond = threading.Condition()
        loaded = [0]
        orig_load = pipeline.load_json

        def coordinating_load(path, *args, **kwargs):
            result = orig_load(path, *args, **kwargs)
            if str(path).endswith("binary-evidence.json"):
                with cond:
                    loaded[0] += 1
                    cond.notify_all()
                    # Pre-lock both threads reach here concurrently and
                    # proceed together into the unserialised window
                    # (lost update). Post-lock the second thread cannot
                    # load until the first saves — the wait times out
                    # and the first proceeds alone.
                    cond.wait_for(lambda: loaded[0] >= 2, timeout=0.5)
            return result

        monkeypatch.setattr(pipeline, "load_json", coordinating_load)

        errs: list[str] = []

        def worker(fd):
            try:
                pipeline.append_fuzz_evidence_to_run(
                    binary, out_dir=tmp_path, fuzz_dir=fd)
            except Exception as exc:  # noqa: BLE001 — surfaced below
                errs.append(f"{fd.name}: {type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=worker, args=(fd,))
                   for fd in fuzz_dirs]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errs, errs
        payload = load_json(tmp_path / "binary-evidence.json")
        tools = sorted(
            item.get("tool") for item in payload["evidence"]
            if isinstance(item, dict))
        assert len(payload["evidence"]) == 2, (
            f"lost update: only {tools} survived")
