"""Suffix-truncation coverage for the proxy-events MAC/seq defence.

The read-side defence (per-line MACs + contiguity check) caught
interior deletion (gap) and mixed forgery (rejected lines), but the
writer derived each batch's sequence base by RECOUNTING the surviving
lines of the target-writable file — so a child that truncated the
SUFFIX (or deleted the whole file) between batches left the next batch
renumbering contiguously from the surviving count: fully verifying,
``integrity == verified``, history silently gone. A planted
symlink/FIFO at the events path suppressed persistence with only a
DEBUG log.

The fix: the writer keeps the run's next-seq in parent memory plus a
MAC'd count sidecar (``proxy-events.count.json``, atomic rename)
updated after every batch, records writer-side tamper flags
(``stream_truncated``, ``persist_open_failure``, ...) MAC-bound in the
sidecar, and the verifier cross-checks the surviving stream against
the sidecar's count. These tests invert the
original proof-of-concept.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux-only sandbox internals",
)

from core.sandbox import context as ctx                   # noqa: E402
from core.sandbox import triage as triage_mod             # noqa: E402
from core.sandbox.proxy import (                          # noqa: E402
    PROXY_EVENTS_COUNT_FILENAME,
    PROXY_EVENTS_FILENAME,
)


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _event(host: str) -> dict:
    return {"host": host, "result": "allowed", "resolved_ip": "1.2.3.4"}


def _persist(run: Path, *hosts: str) -> None:
    ctx._persist_proxy_events([_event(h) for h in hosts], output=str(run))


def _run_dir(tmp_path: Path, name: str = "run") -> Path:
    d = tmp_path / name
    d.mkdir()
    return d


def _events_integrity(run: Path):
    report = triage_mod.triage_run(run, allow_legacy=False)
    assert report is not None
    return report["inputs"]["integrity"]["proxy_events"], report


class TestSuffixTruncation:
    def test_suffix_truncation_between_batches_is_tampered(
        self, tmp_path,
    ):
        run = _run_dir(tmp_path)
        log = run / PROXY_EVENTS_FILENAME
        _persist(run, "exfil-1.example", "exfil-2.example", "c2.example")
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:2]) + "\n")  # erase the c2 event
        _persist(run, "pypi.org")

        integrity, report = _events_integrity(run)
        assert integrity == "tampered"
        assert report["verdict"] == "suspicious"

    def test_whole_file_deletion_between_batches_is_tampered(
        self, tmp_path,
    ):
        run = _run_dir(tmp_path)
        _persist(run, "exfil-1.example", "exfil-2.example")
        (run / PROXY_EVENTS_FILENAME).unlink()
        _persist(run, "pypi.org")

        integrity, report = _events_integrity(run)
        assert integrity == "tampered"

    def test_deletion_after_final_batch_is_tampered(self, tmp_path):
        """No further batch runs after the truncation — the sidecar's
        count alone must catch it."""
        run = _run_dir(tmp_path)
        log = run / PROXY_EVENTS_FILENAME
        _persist(run, "a.example", "b.example", "c.example")
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:1]) + "\n")

        integrity, _ = _events_integrity(run)
        assert integrity == "tampered"

    def test_whole_file_deletion_after_final_batch_is_tampered(
        self, tmp_path,
    ):
        """Events gone entirely, sidecar survives: must produce a
        tampered report, never read as 'no telemetry'."""
        run = _run_dir(tmp_path)
        _persist(run, "a.example")
        (run / PROXY_EVENTS_FILENAME).unlink()

        integrity, _ = _events_integrity(run)
        assert integrity == "tampered"

    def test_sidecar_deleted_alongside_suffix_is_tampered(
        self, tmp_path,
    ):
        """Deleting the sidecar too doesn't help: a stamped stream
        without its count sidecar is tampered under lifecycle
        semantics."""
        run = _run_dir(tmp_path)
        log = run / PROXY_EVENTS_FILENAME
        _persist(run, "a.example", "b.example")
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:1]) + "\n")
        (run / PROXY_EVENTS_COUNT_FILENAME).unlink()

        integrity, _ = _events_integrity(run)
        assert integrity == "tampered"


class TestPlantedObjects:
    def test_planted_fifo_records_mac_bound_tamper_flag(self, tmp_path):
        """A planted FIFO at the events path used to suppress evidence
        with a DEBUG log only. The sidecar now carries
        persist_open_failure inside the MAC."""
        run = _run_dir(tmp_path)
        os.mkfifo(run / PROXY_EVENTS_FILENAME)
        _persist(run, "x.example")

        sidecar = json.loads(
            (run / PROXY_EVENTS_COUNT_FILENAME).read_text())
        assert "persist_open_failure" in sidecar["flags"]
        integrity, report = _events_integrity(run)
        assert integrity == "tampered"
        assert any(
            "persist_open_failure" in e
            for s in report["signals"] if s["type"] == "telemetry_tampering"
            for e in s["evidence"]
        )

    def test_flag_stripping_breaks_the_sidecar_token(self, tmp_path):
        run = _run_dir(tmp_path)
        os.mkfifo(run / PROXY_EVENTS_FILENAME)
        _persist(run, "x.example")
        path = run / PROXY_EVENTS_COUNT_FILENAME
        sidecar = json.loads(path.read_text())
        sidecar["flags"] = []
        path.write_text(json.dumps(sidecar))

        integrity, _ = _events_integrity(run)
        assert integrity == "tampered"


class TestSidecarProvenance:
    def test_forged_sidecar_is_tampered(self, tmp_path):
        run = _run_dir(tmp_path)
        _persist(run, "a.example")
        (run / PROXY_EVENTS_COUNT_FILENAME).write_text(
            json.dumps({"count": 1, "flags": [], "mac": "0" * 64}))

        integrity, _ = _events_integrity(run)
        assert integrity == "tampered"

    def test_sidecar_replayed_from_another_run_is_tampered(
        self, tmp_path,
    ):
        run_a = _run_dir(tmp_path, "run_a")
        run_b = _run_dir(tmp_path, "run_b")
        _persist(run_a, "a.example")
        _persist(run_b, "b.example")
        # Replay run_a's (validly stamped) sidecar into run_b.
        (run_b / PROXY_EVENTS_COUNT_FILENAME).write_bytes(
            (run_a / PROXY_EVENTS_COUNT_FILENAME).read_bytes())

        integrity, _ = _events_integrity(run_b)
        assert integrity == "tampered"


class TestHonestStreams:
    def test_multi_batch_honest_stream_verifies(self, tmp_path):
        run = _run_dir(tmp_path)
        _persist(run, "pypi.org", "crates.io")
        _persist(run, "github.com")

        integrity, report = _events_integrity(run)
        assert integrity == "verified"
        assert report["inputs"]["total_proxy_events"] == 3
        sidecar = json.loads(
            (run / PROXY_EVENTS_COUNT_FILENAME).read_text())
        assert sidecar["count"] == 3
        assert sidecar["flags"] == []

    def test_legacy_run_without_sidecar_still_retriageable(
        self, tmp_path,
    ):
        """Manual re-triage (allow_legacy=True) of a pre-sidecar run:
        stamped events, no sidecar — must not read as tampered."""
        run = _run_dir(tmp_path)
        _persist(run, "a.example")
        (run / PROXY_EVENTS_COUNT_FILENAME).unlink()

        report = triage_mod.triage_run(run, allow_legacy=True)
        assert report["inputs"]["integrity"]["proxy_events"] == "verified"

    def test_cross_process_seeding_from_sidecar(self, tmp_path):
        """A second writer process (fresh parent memory) seeds from
        the verified sidecar: honest interleaved writers keep a
        contiguous, verifying stream."""
        run = _run_dir(tmp_path)
        _persist(run, "a.example", "b.example")
        # Simulate a different process: wipe this process's memory of
        # the stream.
        key = os.path.realpath(str(run / PROXY_EVENTS_FILENAME))
        ctx._PROXY_STREAM_STATE.pop(key, None)
        _persist(run, "c.example")

        integrity, report = _events_integrity(run)
        assert integrity == "verified"
        assert report["inputs"]["total_proxy_events"] == 3

    def test_cross_process_truncation_caught_by_sidecar_seed(
        self, tmp_path,
    ):
        """Truncation between two writer PROCESSES: the second writer
        has no parent memory, but the verified sidecar's count floors
        its seq base — the erased range stays un-renumbered and the
        verifier sees the mismatch."""
        run = _run_dir(tmp_path)
        log = run / PROXY_EVENTS_FILENAME
        _persist(run, "a.example", "b.example")
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:1]) + "\n")
        key = os.path.realpath(str(log))
        ctx._PROXY_STREAM_STATE.pop(key, None)
        _persist(run, "c.example")

        integrity, _ = _events_integrity(run)
        assert integrity == "tampered"


class TestRecountBound:
    def test_recount_is_byte_bounded(self, tmp_path):
        """A planted huge events file must not serialize the parent
        into an unbounded read under the persist lock."""
        count, overflowed = ctx._count_lines_bounded(
            self._big_file(tmp_path), max_bytes=1 << 20)
        assert overflowed is True
        assert count > 0

    @staticmethod
    def _big_file(tmp_path: Path) -> Path:
        p = tmp_path / "big.jsonl"
        with open(p, "wb") as f:
            chunk = (b"x" * 127 + b"\n") * 8192  # 1 MiB
            for _ in range(3):
                f.write(chunk)
        return p


class TestDirectionAttribution:
    def test_crash_window_reads_tampered_with_interrupted_note(
        self, tmp_path,
    ):
        """Events appended but sidecar not yet updated (crash window):
        still fails the verifier, but the evidence names the
        interrupted-persist direction, not truncation."""
        run = _run_dir(tmp_path)
        _persist(run, "a.example")
        # Simulate the crash: replay the batch-1 sidecar after a
        # second batch's events landed.
        saved = (run / PROXY_EVENTS_COUNT_FILENAME).read_bytes()
        _persist(run, "b.example")
        (run / PROXY_EVENTS_COUNT_FILENAME).write_bytes(saved)

        integrity, report = _events_integrity(run)
        assert integrity == "tampered"
        notes = [
            e
            for s_ in report["signals"]
            if s_["type"] == "telemetry_tampering"
            for e in s_["evidence"]
        ]
        assert any("interrupted persist" in n or "AHEAD" in n
                   for n in notes)
        assert not any("suffix truncation" in n for n in notes)

    def test_truncation_keeps_the_erasure_note(self, tmp_path):
        run = _run_dir(tmp_path)
        log = run / PROXY_EVENTS_FILENAME
        _persist(run, "a.example", "b.example")
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:1]) + "\n")

        integrity, report = _events_integrity(run)
        assert integrity == "tampered"
        notes = [
            e
            for s_ in report["signals"]
            if s_["type"] == "telemetry_tampering"
            for e in s_["evidence"]
        ]
        assert any("suffix truncation" in n for n in notes)


class TestAnchoredOverflow:
    @pytest.mark.slow
    def test_real_oversize_anchored_stream_verifies_end_to_end(
        self, tmp_path,
    ):
        """An honest anchored stream LARGER than the whole-file triage
        input bound (64 MiB) must grade clean through the REAL path —
        no caps monkeypatched. This synthesizes a genuine >64 MiB
        multi-batch run: the writer side must leave an empty flag set
        (the recount overflow is anchored), and strict triage must
        stream-verify every event instead of refusing the file and
        misreading the refusal as truncation.

        slow: writing + stream-verifying >64 MiB of real events takes
        tens of seconds by construction (the whole point is that no
        cap is mocked down) — nightly tier, per the default-tier
        slow-test guard's doctrine."""
        run = _run_dir(tmp_path)
        n_batches, per_batch = 4, 100_000
        batch_hosts = [
            f"host-{i:06d}.padpadpadpadpadpadpadpadpadpadpadpadpad"
            f"padpadpadpadpadpadpadpadpadpadpadpad.example"
            for i in range(per_batch)
        ]
        for b in range(n_batches):
            ctx._persist_proxy_events(
                [{"host": h, "result": "allowed",
                  "resolved_ip": "10.0.0.1"} for h in batch_hosts],
                output=str(run),
            )
        size = (run / PROXY_EVENTS_FILENAME).stat().st_size
        assert size > 64 * 1024 * 1024, (
            f"synthesis must exceed the whole-file input bound "
            f"(got {size} bytes)"
        )
        sidecar = json.loads(
            (run / PROXY_EVENTS_COUNT_FILENAME).read_text())
        assert sidecar["flags"] == []
        assert sidecar["count"] == n_batches * per_batch

        integrity, report = _events_integrity(run)
        assert integrity == "verified"
        assert report["verdict"] == "clean"
        assert (report["inputs"]["total_proxy_events"]
                == n_batches * per_batch)

    def test_stream_past_the_streaming_bound_gets_the_over_bound_note(
        self, tmp_path, monkeypatch,
    ):
        """Past the (much larger) streaming caps a genuine residual
        remains: the tail is unverified, so the run fails toward
        suspicious — but with the DISTINCT over-bound note, never the
        truncation/erasure one. (Caps monkeypatched here; the
        real-size crossing of the whole-file bound is exercised
        un-mocked above.)"""
        run = _run_dir(tmp_path)
        _persist(run, *(f"h{i}.example" for i in range(8)))
        monkeypatch.setattr(triage_mod, "_MAX_EVENTS_PARSED", 5)

        integrity, report = _events_integrity(run)
        assert integrity == "tampered"
        notes = [
            e
            for s_ in report["signals"]
            if s_["type"] == "telemetry_tampering"
            for e in s_["evidence"]
        ]
        assert any("exceeds the triage streaming bound" in n
                   for n in notes)
        assert not any("suffix truncation" in n for n in notes)

    def test_unanchored_oversize_stream_flags(self, tmp_path, monkeypatch):
        orig = ctx._count_lines_bounded

        def capped(path, max_bytes=64):
            return orig(path, max_bytes)

        monkeypatch.setattr(ctx, "_count_lines_bounded", capped)
        run = _run_dir(tmp_path)
        # Foreign >cap stream with NO sidecar and no parent memory.
        (run / PROXY_EVENTS_FILENAME).write_text(
            "".join(json.dumps({"host": f"x{i}"}) + "\n"
                    for i in range(20)))
        _persist(run, "a.example")

        sidecar = json.loads(
            (run / PROXY_EVENTS_COUNT_FILENAME).read_text())
        assert "recount_overflow" in sidecar["flags"]
        integrity, _ = _events_integrity(run)
        assert integrity == "tampered"


class TestParentMemoryFloor:
    """Delta over the sidecar mechanism: simultaneous erasure of the
    events file AND its count sidecar is on-disk-consistent (the
    sidecar design's documented residual) — the parent-memory mirror
    closes it for in-lifecycle triage."""

    def _persist(self, out, n):
        import core.sandbox.context as context_mod
        events = [{"host": f"h{i}.example", "port": 443,
                   "result": "denied_host"} for i in range(n)]
        context_mod._persist_proxy_events(events, output=str(out))

    def test_both_artifacts_erased_reads_as_tampering(
            self, tmp_path, monkeypatch):
        import core.sandbox.context as context_mod
        from core.sandbox import summary as summary_mod
        from core.sandbox import triage as triage_mod
        monkeypatch.setattr(summary_mod, "_proxy_persist_state", {})
        monkeypatch.setattr(context_mod, "_PROXY_STREAM_STATE", {})
        self._persist(tmp_path, 3)
        (tmp_path / triage_mod.PROXY_EVENTS_FILENAME).unlink()
        (tmp_path / triage_mod.PROXY_EVENTS_COUNT_FILENAME).unlink()
        report = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert report is not None, (
            "erasing both artifacts must not read as no-telemetry "
            "while the parent's own record says events existed")
        assert report["inputs"]["integrity"]["proxy_events"] == (
            "tampered")
        assert any("parent-memory" in str(sig.get("evidence"))
                   for sig in report["signals"]
                   if sig["type"] == "telemetry_tampering")

    def test_parent_memory_never_excuses(self, tmp_path, monkeypatch):
        """A consistent on-disk stream + sidecar stays verified even
        when parent memory has a LOWER count (one-way floor)."""
        import core.sandbox.context as context_mod
        from core.sandbox import summary as summary_mod
        from core.sandbox import triage as triage_mod
        monkeypatch.setattr(summary_mod, "_proxy_persist_state", {})
        monkeypatch.setattr(context_mod, "_PROXY_STREAM_STATE", {})
        self._persist(tmp_path, 2)
        self._persist(tmp_path, 1)
        report = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert report is not None
        assert report["inputs"]["integrity"]["proxy_events"] == (
            "verified")

    def test_fresh_process_retriage_unaffected(self, tmp_path,
                                               monkeypatch):
        """No parent memory (fresh process) keeps the sidecar-only
        semantics — the documented residual stays documented for
        post-hoc re-triage, no false tampering."""
        import core.sandbox.context as context_mod
        from core.sandbox import summary as summary_mod
        from core.sandbox import triage as triage_mod
        monkeypatch.setattr(summary_mod, "_proxy_persist_state", {})
        monkeypatch.setattr(context_mod, "_PROXY_STREAM_STATE", {})
        self._persist(tmp_path, 3)
        (tmp_path / triage_mod.PROXY_EVENTS_FILENAME).unlink()
        (tmp_path / triage_mod.PROXY_EVENTS_COUNT_FILENAME).unlink()
        monkeypatch.setattr(summary_mod, "_proxy_persist_state", {})
        report = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert report is None
