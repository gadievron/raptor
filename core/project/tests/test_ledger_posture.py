"""Run-posture ledger records — grammar, full-path keying, dedup,
pruning, collision detection, MAC trust binding, and the
registered-session gates.

The posture line persists the run's FINAL telemetry-key posture into
the parent-owned session ledger so a fresh-process triage can grade
run evidence after the recording process is gone. The record is keyed
by the FULL resolved run-dir path: telemetry MACs bind only the
directory basename, so the full-path key is what lets a reader tell a
genuine record from one minted for a same-named sibling run. The
registry LOCATION is env-steerable (``HOME`` /
``RAPTOR_REGISTRY_HOME`` survive ``get_safe_env()``), so each line
carries an HMAC under the pwd-derived telemetry key and the reader
grades evidence only from records that verify.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project import sessions
from core.sandbox import telemetry_mac

DEAD_PID = 999999999

#: A posture every encoder path accepts — the mandatory fact present.
HIDDEN = {"mount_ns_active": True, "restrict_reads": False,
          "mac_key_hidden": True}
EXPOSED = {"mount_ns_active": False, "restrict_reads": False,
           "mac_key_hidden": False}

#: Compact-JSON facts token matching the encoder's output for a
#: minimal key-hidden posture — used by tests that hand-craft lines.
HIDDEN_FACTS = '{"mac_key_hidden":true}'
EXPOSED_FACTS = '{"mac_key_hidden":false}'


class _LedgerPostureCase(unittest.TestCase):
    """Isolated SESSIONS_DIR + a registered claude-shaped self + a
    scratch telemetry-key store (the key path is pwd-derived — an
    unpinned test would mint against the operator's REAL key)."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.sessions_dir = Path(self._tmp.name) / "sessions.d"
        self.run_root = Path(self._tmp.name) / "runs"
        self.run_root.mkdir()
        key_home = Path(self._tmp.name) / "tm-data"
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch.object(sessions, "_comm",
                         lambda pid: "claude" if pid == os.getpid()
                         else None),
            patch.object(telemetry_mac, "_data_home", lambda: key_home),
        ):
            p.start()
            self.addCleanup(p.stop)
        sessions.record_session("posturelane", pid=os.getpid())

    def _mk_run(self, name: str, parent: Path | None = None) -> Path:
        d = (parent or self.run_root) / name
        d.mkdir(parents=True)
        return d

    def _ledger_text(self, pid: int | None = None) -> str:
        path = self.sessions_dir / f"{pid or os.getpid()}.run"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def _minted_line(self, epoch: int, facts: str, run_dir: Path) -> str:
        """A posture line stamped like the genuine writer would."""
        resolved = str(run_dir.resolve())
        token = telemetry_mac.mint(
            telemetry_mac.run_posture_fields(epoch, facts, resolved))
        assert token is not None
        return f"posture {epoch} {facts} {token} {resolved}\n"

    def _append_own_ledger(self, lines: str) -> None:
        """Simulate an attacker-stocked ledger: raw line append."""
        path = self.sessions_dir / f"{os.getpid()}.run"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(lines)


class RecordAndReadTest(_LedgerPostureCase):
    def test_roundtrip_keyed_by_full_resolved_path(self):
        d = self._mk_run("scan_1")
        self.assertTrue(sessions.ledger_record_posture(
            d, HIDDEN, pid=os.getpid()))
        posture, collision = sessions.ledger_run_posture(d)
        self.assertEqual(posture, HIDDEN)
        self.assertFalse(collision)
        # The line carries the FULL resolved path, not the basename.
        self.assertIn(f" {d.resolve()}\n", self._ledger_text())

    def test_unknown_run_reads_none(self):
        d = self._mk_run("scan_unrecorded")
        self.assertEqual(sessions.ledger_run_posture(d), (None, False))

    def test_rerecord_replaces_not_accumulates(self):
        d = self._mk_run("scan_2")
        sessions.ledger_record_posture(d, HIDDEN, pid=os.getpid())
        sessions.ledger_record_posture(d, EXPOSED, pid=os.getpid())
        posture, _ = sessions.ledger_run_posture(d)
        self.assertEqual(posture, EXPOSED)
        self.assertEqual(self._ledger_text().count("posture "), 1)

    def test_non_portable_facts_are_filtered(self):
        d = self._mk_run("scan_3")
        self.assertTrue(sessions.ledger_record_posture(d, {
            "mac_key_hidden": True,
            "containment_tier": "namespace",   # token string: kept
            "note": "has a space",             # non-token string: dropped
            "weird key": True,                 # non-token key: dropped
            "count": 3,                        # non-bool/str: dropped
        }, pid=os.getpid()))
        posture, _ = sessions.ledger_run_posture(d)
        self.assertEqual(posture, {"mac_key_hidden": True,
                                   "containment_tier": "namespace"})

    def test_record_without_mac_key_hidden_is_refused(self):
        d = self._mk_run("scan_4")
        self.assertFalse(sessions.ledger_record_posture(
            d, {"mount_ns_active": True}, pid=os.getpid()))
        self.assertFalse(sessions.ledger_record_posture(
            d, {"mac_key_hidden": "yes"}, pid=os.getpid()))
        self.assertEqual(sessions.ledger_run_posture(d), (None, False))

    def test_invalid_run_dir_is_refused(self):
        d = self.run_root / "scan 5"  # space in basename
        d.mkdir()
        self.assertFalse(sessions.ledger_record_posture(
            d, HIDDEN, pid=os.getpid()))

    def test_unregistered_session_cannot_record(self):
        d = self._mk_run("scan_6")
        self.assertFalse(sessions.ledger_record_posture(
            d, HIDDEN, pid=DEAD_PID))


class CollisionTest(_LedgerPostureCase):
    """Full-path keying: a same-basename sibling is a conflict, never
    a match — the cross-run replay signature the basename-only MAC
    run-binding cannot see."""

    def test_same_basename_different_path_is_collision_not_match(self):
        a = self._mk_run("scan_9", parent=self.run_root / "a")
        b = self._mk_run("scan_9", parent=self.run_root / "b")
        sessions.ledger_record_posture(a, HIDDEN, pid=os.getpid())
        self.assertEqual(sessions.ledger_run_posture(b), (None, True))
        # The genuine dir still reads its own record, no collision.
        self.assertEqual(sessions.ledger_run_posture(a), (HIDDEN, False))

    def test_exact_match_suppresses_sibling_collision(self):
        a = self._mk_run("scan_9", parent=self.run_root / "a")
        b = self._mk_run("scan_9", parent=self.run_root / "b")
        sessions.ledger_record_posture(a, EXPOSED, pid=os.getpid())
        sessions.ledger_record_posture(b, HIDDEN, pid=os.getpid())
        self.assertEqual(sessions.ledger_run_posture(b), (HIDDEN, False))


class CrossLedgerTest(_LedgerPostureCase):
    def _foreign_ledger(self, lines: str, pid: int = 777777,
                        with_entry: bool = True):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        if with_entry:
            (self.sessions_dir / str(pid)).write_text(
                "project=posturelane\nsince=x\n", encoding="utf-8")
        (self.sessions_dir / f"{pid}.run").write_text(
            lines, encoding="utf-8")

    def test_newest_record_wins_across_sessions(self):
        d = self._mk_run("scan_7")
        self._foreign_ledger(self._minted_line(100, EXPOSED_FACTS, d))
        sessions.ledger_record_posture(d, HIDDEN, pid=os.getpid())
        posture, _ = sessions.ledger_run_posture(d)
        self.assertTrue(posture["mac_key_hidden"])

    def test_orphan_ledger_never_steers(self):
        d = self._mk_run("scan_8")
        self._foreign_ledger(self._minted_line(100, HIDDEN_FACTS, d),
                             with_entry=False)
        self.assertEqual(sessions.ledger_run_posture(d), (None, False))

    def test_malformed_posture_lines_read_as_unknown(self):
        d = self._mk_run("scan_10")
        mac = "0" * 64
        self._foreign_ledger(
            f"posture 100 notjson {mac} {d.resolve()}\n"
            f"posture 100 [1,2] {mac} {d.resolve()}\n"
            f'posture 100 {{"mac_key_hidden":"y"}} {mac} {d.resolve()}\n')
        self.assertEqual(sessions.ledger_run_posture(d), (None, False))


class RewriteSurvivalTest(_LedgerPostureCase):
    def _mk_lifecycle_run(self, name: str) -> Path:
        d = self._mk_run(name)
        (d / ".raptor-run.json").write_text(
            '{"status": "running"}', encoding="utf-8")
        return d

    def test_posture_survives_record_start_rewrites(self):
        d = self._mk_run("kept_run")
        sessions.ledger_record_posture(d, HIDDEN, pid=os.getpid())
        other = self._mk_lifecycle_run("other_run")
        sessions.ledger_record_start(other, pid=os.getpid())
        sessions.ledger_record_finish(other, "completed", pid=os.getpid())
        self.assertEqual(sessions.ledger_run_posture(d), (HIDDEN, False))

    def test_vanished_run_dir_records_are_pruned_on_write(self):
        gone = self._mk_run("gone_run")
        sessions.ledger_record_posture(gone, HIDDEN, pid=os.getpid())
        gone_path = str(gone.resolve())
        gone.rmdir()
        kept = self._mk_run("kept_run")
        sessions.ledger_record_posture(kept, HIDDEN, pid=os.getpid())
        self.assertNotIn(gone_path, self._ledger_text())
        self.assertEqual(sessions.ledger_run_posture(kept),
                         (HIDDEN, False))

    def test_foreign_unknown_lines_survive_posture_writes(self):
        d = self._mk_run("scan_11")
        pid = os.getpid()
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.sessions_dir / f"{pid}.run").write_text(
            "future-line kept verbatim\n", encoding="utf-8")
        sessions.ledger_record_posture(d, HIDDEN, pid=pid)
        self.assertIn("future-line kept verbatim\n", self._ledger_text())


class TrustBindingTest(_LedgerPostureCase):
    """The registry LOCATION is env-steerable (``HOME`` /
    ``RAPTOR_REGISTRY_HOME`` survive ``get_safe_env()``), so the MAC —
    not the directory a record was found in — is what gets trusted.
    Every forgery shape must read as posture UNKNOWN, the fail-closed
    direction triage acts on."""

    def test_forged_record_without_valid_mac_is_ignored(self):
        d = self._mk_run("scan_12")
        self._append_own_ledger(
            f"posture 100 {HIDDEN_FACTS} - {d.resolve()}\n"
            f"posture 100 {HIDDEN_FACTS} {'0' * 64} {d.resolve()}\n"
            # Pre-MAC grammar: a replayed 3-token line must not
            # restore strict admission either.
            f"posture 100 {HIDDEN_FACTS} {d.resolve()}\n")
        self.assertEqual(sessions.ledger_run_posture(d), (None, False))

    def test_record_replayed_under_other_path_fails(self):
        a = self._mk_run("scan_13", parent=self.run_root / "a")
        b = self._mk_run("scan_13", parent=self.run_root / "b")
        c = self._mk_run("scan_14")
        sessions.ledger_record_posture(a, HIDDEN, pid=os.getpid())
        line = next(ln for ln in self._ledger_text().splitlines()
                    if ln.startswith("posture "))
        self._append_own_ledger(
            line.replace(str(a.resolve()), str(b.resolve())) + "\n")
        self._append_own_ledger(
            line.replace(str(a.resolve()), str(c.resolve())) + "\n")
        # Same basename elsewhere: the replay signature, never a
        # posture. Different basename: nothing at all.
        self.assertEqual(sessions.ledger_run_posture(b), (None, True))
        self.assertEqual(sessions.ledger_run_posture(c), (None, False))
        # The genuine record still reads back untouched.
        self.assertEqual(sessions.ledger_run_posture(a), (HIDDEN, False))

    def test_unverified_newer_record_cannot_shadow_verified(self):
        d = self._mk_run("scan_15")
        sessions.ledger_record_posture(d, HIDDEN, pid=os.getpid())
        self._append_own_ledger(
            f"posture {'9' * 20} {EXPOSED_FACTS} {'0' * 64} "
            f"{d.resolve()}\n")
        self.assertEqual(sessions.ledger_run_posture(d), (HIDDEN, False))

    def test_unstamped_write_reads_unknown(self):
        d = self._mk_run("scan_16")
        with patch.object(telemetry_mac, "mint", lambda fields: None):
            self.assertTrue(sessions.ledger_record_posture(
                d, HIDDEN, pid=os.getpid()))
        self.assertIn(" - ", self._ledger_text())
        self.assertEqual(sessions.ledger_run_posture(d), (None, False))


class HostileLineTest(_LedgerPostureCase):
    """A same-UID line-appender must not be able to block posture
    recording or crash the reader: the bounded epoch keeps ``int()``
    away from Python's int-str conversion limit (ValueError past
    ~4300 digits) inside the writer's dedup scan, and a deep-nested
    facts token's RecursionError stays inside the line parser."""

    def test_oversized_epoch_line_cannot_block_recording(self):
        d = self._mk_run("scan_17")
        sessions.ledger_record_posture(d, HIDDEN, pid=os.getpid())
        self._append_own_ledger(
            f"posture {'9' * 5000} {HIDDEN_FACTS} {d.resolve()}\n"
            f"posture {'9' * 5000} {HIDDEN_FACTS} {'0' * 64} "
            f"{d.resolve()}\n")
        self.assertTrue(sessions.ledger_record_posture(
            d, EXPOSED, pid=os.getpid()))
        self.assertEqual(sessions.ledger_run_posture(d),
                         (EXPOSED, False))

    def test_deep_nested_facts_line_cannot_block_recording(self):
        """A facts token of deep-nested JSON drives ``json.loads``
        into RecursionError, which is NOT a ValueError — it must read
        as just another malformed line, on the writer's dedup scan and
        the reader's cross-ledger sweep alike."""
        d = self._mk_run("scan_18")
        sessions.ledger_record_posture(d, HIDDEN, pid=os.getpid())
        self._append_own_ledger(
            f"posture 100 {'[' * 60000} {'0' * 64} {d.resolve()}\n")
        self.assertTrue(sessions.ledger_record_posture(
            d, EXPOSED, pid=os.getpid()))
        self.assertEqual(sessions.ledger_run_posture(d),
                         (EXPOSED, False))


if __name__ == "__main__":
    unittest.main()
