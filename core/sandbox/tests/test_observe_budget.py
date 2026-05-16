"""Tests for AuditBudget truncation surfacing in observe-mode.

When a probe produces more records than the AuditBudget caps allow,
the tracer drops the excess and writes a summary record at end-of-run
listing per-category drop counts. Without surfacing that to the
operator, they'd see a profile with N records and assume that's
everything the binary did — silently incomplete.

This module covers:

  * Parser reads the audit_summary tail record and populates
    ``ObserveProfile.budget_truncated`` + ``dropped_by_category``.
  * Parser drops a spoofed audit_summary that lacks the right nonce
    (a target binary writing a fake summary claiming truncation
    won't lie its way past nonce validation).
  * CLI ``--json`` and human summary surface the truncation warning
    when present.
  * End-to-end with a real workload + tiny budget — the summary
    record's drop counts are visible in the resulting profile.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from core.sandbox.observe_profile import (
    OBSERVE_FILENAME, ObserveProfile, parse_observe_log,
)


# ---------------------------------------------------------------------------
# Parser — surfacing audit_summary
# ---------------------------------------------------------------------------


def _summary_record(nonce: str = "n", *,
                    dropped: dict = None,
                    total: int = 100) -> dict:
    return {
        "ts": "2026-05-08T00:00:00Z",
        "type": "audit_summary",
        "audit": True,
        "total_records": total,
        "dropped_by_category": dropped or {},
        "category_counts": {},
        "pid_counts": {},
        "global_cap": 1000,
        "nonce": nonce,
    }


def _open_record(nonce: str, path: str = "/etc/x") -> dict:
    return {
        "ts": "2026-05-08T00:00:00Z",
        "syscall": "openat",
        "syscall_nr": 257,
        "args": [-100, 0, 0, 0, 0, 0],
        "path": path,
        "target_pid": 1234,
        "type": "write",
        "observe": True,
        "nonce": nonce,
    }


def _write_jsonl(p: Path, recs: list) -> None:
    with p.open("w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")


class TestParserSurfacesTruncation:

    def test_truncated_summary_sets_flag_and_drops(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _open_record("nonce-1", "/lib/libc.so"),
            _summary_record("nonce-1", dropped={
                "write": 42, "network": 7,
            }),
        ])
        p = parse_observe_log(tmp_path, expected_nonce="nonce-1")
        assert p.budget_truncated is True
        assert p.dropped_by_category == {"write": 42, "network": 7}

    def test_summary_without_drops_does_not_set_flag(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _open_record("nonce-1"),
            _summary_record("nonce-1", dropped={"write": 0}),
        ])
        p = parse_observe_log(tmp_path, expected_nonce="nonce-1")
        assert p.budget_truncated is False
        # dropped_by_category retains the zero-count entries — the
        # parser doesn't filter them, so callers can see "we
        # checked, no drops".
        assert p.dropped_by_category == {"write": 0}

    def test_no_summary_means_default_state(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _open_record("nonce-1"),
        ])
        p = parse_observe_log(tmp_path, expected_nonce="nonce-1")
        assert p.budget_truncated is False
        assert p.dropped_by_category == {}


class TestSpoofedSummaryRejected:
    """A target binary writing a fake audit_summary into the JSONL
    cannot get the parser to set budget_truncated=True. The summary
    record carries the per-run nonce; without a matching value the
    parser drops it (same gate as syscall records)."""

    def test_summary_with_wrong_nonce_filtered(self, tmp_path):
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            # Real records from the trusted tracer.
            _open_record("nonce-real", "/lib/libc.so"),
            # Spoofed summary written by the target binary inside
            # the sandbox. Without the right nonce the parser drops
            # it, so budget_truncated stays False.
            _summary_record("nonce-FAKE", dropped={"write": 999}),
            # Real summary from the tracer — no drops.
            _summary_record("nonce-real", dropped={"write": 0}),
        ])
        p = parse_observe_log(tmp_path, expected_nonce="nonce-real")
        assert p.budget_truncated is False, (
            "spoofed summary must not be allowed to claim truncation"
        )
        assert p.dropped_by_category == {"write": 0}

    def test_summary_without_nonce_filtered_when_expected_set(
        self, tmp_path,
    ):
        rec = _summary_record("ignored")
        del rec["nonce"]
        _write_jsonl(tmp_path / OBSERVE_FILENAME, [
            _open_record("nonce-real", "/x"),
            rec,
        ])
        p = parse_observe_log(tmp_path, expected_nonce="nonce-real")
        assert p.budget_truncated is False


# ---------------------------------------------------------------------------
# CLI surfacing
# ---------------------------------------------------------------------------


class TestCliSummaryRendersTruncation:

    def test_format_summary_emits_warning_when_truncated(self, tmp_path):
        from core.sandbox.observe_cli import _format_summary

        prof = ObserveProfile(
            paths_read=["/x"],
            budget_truncated=True,
            dropped_by_category={"write": 42, "network": 0},
        )
        out = _format_summary(prof, run_dir=tmp_path, kept=False,
                              return_code=0)
        assert "budget truncated" in out
        assert "42" in out
        assert "'write'" in out
        # Zero-count entries are NOT rendered — operators want
        # signal, not noise.
        assert "'network'" not in out
        assert "audit-budget" in out

    def test_format_summary_no_warning_when_not_truncated(self, tmp_path):
        from core.sandbox.observe_cli import _format_summary

        prof = ObserveProfile(paths_read=["/x"])
        out = _format_summary(prof, run_dir=tmp_path, kept=False,
                              return_code=0)
        assert "budget truncated" not in out

    def test_json_carries_truncation_fields(self, tmp_path):
        from core.sandbox.observe_cli import _profile_to_json

        prof = ObserveProfile(
            paths_read=["/x"],
            budget_truncated=True,
            dropped_by_category={"write": 42},
        )
        s = _profile_to_json(prof, run_dir=tmp_path, kept=False,
                             return_code=0)
        loaded = json.loads(s)
        assert loaded["budget_truncated"] is True
        assert loaded["dropped_by_category"] == {"write": 42}


# ---------------------------------------------------------------------------
# End-to-end — small budget forces overflow on a real probe
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Real tracer-budget E2E — Linux ptrace + seccomp",
)
class TestEndToEndBudgetOverflow(unittest.TestCase):
    """Run a workload that opens many files under a tiny global cap;
    confirm the summary record with non-zero drops surfaces in the
    parsed profile."""

    def setUp(self):
        from core.sandbox.probes import check_net_available
        from core.sandbox.seccomp import check_seccomp_available
        from core.sandbox.ptrace_probe import check_ptrace_available
        if not (check_net_available()
                and check_seccomp_available()
                and check_ptrace_available()):
            self.skipTest("observe prerequisites unavailable")

    def test_small_budget_overflows_and_summary_visible(self):
        # Force a tiny global cap via state. Workload opens ~100
        # files; with cap < 50 the budget overflows.
        from core.sandbox import run as sandbox_run
        from core.sandbox import state

        prev = getattr(state, "_cli_sandbox_audit_budget", None)
        state._cli_sandbox_audit_budget = 30
        try:
            with TemporaryDirectory() as d:
                run_dir = Path(d)
                workload = (
                    "find /usr/lib/locale -maxdepth 2 -type f "
                    "2>/dev/null | head -100 | "
                    "xargs -I{} cat {} > /dev/null 2>&1; true"
                )
                result = sandbox_run(
                    ["/bin/sh", "-c", workload],
                    target=str(run_dir), output=str(run_dir),
                    observe=True, capture_output=True, text=True,
                    timeout=30,
                )
                nonce = result.sandbox_info.get("observe_nonce")
                if nonce is None:
                    self.skipTest("audit didn't engage")

                profile = parse_observe_log(
                    run_dir, expected_nonce=nonce,
                )
                # Budget was tiny — should have truncated.
                self.assertTrue(
                    profile.budget_truncated,
                    f"profile not flagged truncated despite tiny "
                    f"budget; dropped_by_category="
                    f"{profile.dropped_by_category!r}",
                )
                # At least one category dropped > 0 records.
                self.assertTrue(
                    any(v > 0 for v in
                        profile.dropped_by_category.values()),
                    f"no category showed drops; got "
                    f"{profile.dropped_by_category!r}",
                )
        finally:
            state._cli_sandbox_audit_budget = prev


if __name__ == "__main__":
    unittest.main()
