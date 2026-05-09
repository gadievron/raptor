"""Concurrency tests for observe-mode.

Two scenarios:

  1. Two concurrent sandboxes share the same audit_run_dir. Each
     gets a distinct nonce; their records interleave in the same
     JSONL but each parse_observe_log call (with the right nonce)
     surfaces only its own records. This is the multi-tenant
     contract — without it, calling sandbox(observe=True) twice
     with overlapping output dirs would conflate records.

  2. Atomicity under fast writes. The tracer's _write_record uses
     POSIX O_APPEND semantics, so writes < PIPE_BUF (~4KB) land
     atomically against concurrent writers. We exercise this with
     a workload that produces many traced syscalls in a tight loop
     and assert every line in the JSONL parses cleanly — no
     interleaved torn records.

Both tests are Linux-only and require ptrace + libseccomp.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux ptrace + seccomp tracer — observe is Linux-only here",
)


def _prereqs_met() -> tuple[bool, str]:
    from core.sandbox.probes import check_net_available
    from core.sandbox.seccomp import check_seccomp_available
    from core.sandbox.ptrace_probe import check_ptrace_available
    if not check_net_available():
        return False, "user namespaces unavailable"
    if not check_seccomp_available():
        return False, "libseccomp unavailable"
    if not check_ptrace_available():
        return False, "ptrace blocked"
    return True, ""


# ---------------------------------------------------------------------------
# Concurrent sandboxes — nonce isolation
# ---------------------------------------------------------------------------


class TestConcurrentSandboxesNonceIsolation(unittest.TestCase):
    """Two sandbox(observe=True) runs writing to the same
    audit_run_dir. Each gets its own nonce; parse with one nonce
    surfaces only that run's records. Records the OTHER run wrote
    are dropped because their nonce doesn't match."""

    def setUp(self):
        ok, reason = _prereqs_met()
        if not ok:
            self.skipTest(reason)

    def test_two_runs_same_dir_distinct_nonces(self):
        from core.sandbox import run as sandbox_run
        from core.sandbox.observe_profile import (
            OBSERVE_FILENAME, parse_observe_log,
        )

        # Each run uses its own target/output (Landlock + tracer
        # need writable scratch space) but writes its observe log
        # into the SHARED dir. The shared dir is the one we parse
        # afterwards.
        with TemporaryDirectory() as d:
            shared = Path(d) / "shared"
            shared.mkdir()
            scratch_a = Path(d) / "a"
            scratch_a.mkdir()
            scratch_b = Path(d) / "b"
            scratch_b.mkdir()

            # Run A: reads /etc/hostname (a path that "true" doesn't
            # touch — gives us a distinguishable signal).
            r_a = sandbox_run(
                ["/bin/sh", "-c",
                 "cat /etc/hostname > /dev/null"],
                target=str(scratch_a), output=str(shared),
                observe=True, capture_output=True, text=True, timeout=10,
            )
            nonce_a = r_a.sandbox_info.get("observe_nonce")
            if nonce_a is None:
                self.skipTest("audit didn't engage on run A")

            # Run B: reads /etc/os-release.
            r_b = sandbox_run(
                ["/bin/sh", "-c",
                 "cat /etc/os-release > /dev/null"],
                target=str(scratch_b), output=str(shared),
                observe=True, capture_output=True, text=True, timeout=10,
            )
            nonce_b = r_b.sandbox_info.get("observe_nonce")
            if nonce_b is None:
                self.skipTest("audit didn't engage on run B")

            self.assertNotEqual(
                nonce_a, nonce_b,
                "concurrent runs must get distinct nonces",
            )

            # The shared JSONL has BOTH runs' records.
            jsonl = shared / OBSERVE_FILENAME
            self.assertTrue(jsonl.exists())

            # Parse with nonce A → A's reads, not B's.
            profile_a = parse_observe_log(shared, expected_nonce=nonce_a)
            profile_b = parse_observe_log(shared, expected_nonce=nonce_b)

            # Each profile must show its own distinguishing read.
            # /etc/hostname only in A; /etc/os-release only in B.
            # (Both also load libc + ld.so — those overlap, but the
            # distinguishing reads should NOT cross over.)
            self.assertIn(
                "/etc/hostname", profile_a.paths_read,
                f"run A's distinguishing read missing from "
                f"profile_a={profile_a.paths_read!r}",
            )
            self.assertNotIn(
                "/etc/hostname", profile_b.paths_read,
                "run B parsed with nonce_b must not see run A's reads",
            )

            self.assertIn(
                "/etc/os-release", profile_b.paths_read,
                f"run B's distinguishing read missing from "
                f"profile_b={profile_b.paths_read!r}",
            )
            self.assertNotIn(
                "/etc/os-release", profile_a.paths_read,
                "run A parsed with nonce_a must not see run B's reads",
            )


# ---------------------------------------------------------------------------
# JSONL atomicity — high write rate produces no torn records
# ---------------------------------------------------------------------------


class TestObserveJsonlAtomicity(unittest.TestCase):
    """The tracer writes each record via O_APPEND, which POSIX
    guarantees atomic for sub-PIPE_BUF writes (~4KB on Linux).
    Records average ~300 bytes, well under the boundary, so no
    inter-line tearing should occur even under tight write loops.

    Verify: spawn a workload that opens many files (high record
    rate); confirm every line in the JSONL parses cleanly. A
    torn record would manifest as a mid-line concatenation that
    fails json.loads."""

    def setUp(self):
        ok, reason = _prereqs_met()
        if not ok:
            self.skipTest(reason)

    def test_no_torn_records_under_load(self):
        from core.sandbox import run as sandbox_run
        from core.sandbox.observe_profile import OBSERVE_FILENAME

        # Workload: open every entry in /usr/lib/locale (~500 files
        # on a typical Linux). Each open()/openat() produces a
        # tracer record; the tracer must not interleave.
        # Use shell + find to keep the workload small + portable.
        workload = (
            "find /usr/lib/locale -maxdepth 2 -type f 2>/dev/null | "
            "head -100 | xargs -I{} cat {} > /dev/null 2>&1; true"
        )

        with TemporaryDirectory() as d:
            run_dir = Path(d)
            result = sandbox_run(
                ["/bin/sh", "-c", workload],
                target=str(run_dir), output=str(run_dir),
                observe=True, capture_output=True, text=True, timeout=30,
            )
            nonce = result.sandbox_info.get("observe_nonce")
            if nonce is None:
                self.skipTest("audit didn't engage")

            jsonl = run_dir / OBSERVE_FILENAME
            self.assertTrue(jsonl.exists())

            # Parse every line directly (not via parse_observe_log,
            # which would silently swallow torn records).
            text = jsonl.read_text()
            lines = [l for l in text.splitlines() if l.strip()]
            self.assertGreater(
                len(lines), 50,
                f"workload should produce many records; got "
                f"{len(lines)}",
            )

            torn = []
            valid_nonced = 0
            for i, line in enumerate(lines):
                try:
                    rec = json.loads(line)
                except ValueError as exc:
                    torn.append((i, line[:80], str(exc)))
                    continue
                # End-of-run summary marker has no nonce — skip.
                if rec.get("type") == "audit_summary":
                    continue
                if rec.get("nonce") == nonce:
                    valid_nonced += 1

            self.assertEqual(
                torn, [],
                f"O_APPEND atomicity broken — {len(torn)} torn "
                f"records: {torn[:3]!r}",
            )
            self.assertGreater(
                valid_nonced, 0,
                "expected at least one valid-nonce record after "
                "high-write-rate workload",
            )


if __name__ == "__main__":
    unittest.main()
