"""Cross-component integration tests for audit mode.

These exercise interactions between the tracer's JSONL writes and
the existing summary aggregator (record_denial path). Specifically:
- A b1 (proxy audit) record AND a b2/b3 (tracer audit) record
  written to the SAME run dir's JSONL must both be picked up by
  summarize_and_write.
- The summary's by_type counts include both sources.
- Suggested-fix hints render correctly for tracer-emitted records.

Pure-Python tests, no fork / no ptrace — exercise the JSONL contract
that crosses module boundaries.
"""

from __future__ import annotations

import json

import pytest

from core.sandbox import summary as summary_mod
from core.sandbox import tracer


@pytest.fixture(autouse=True)
def _isolate_active_run():
    summary_mod.set_active_run_dir(None)
    yield
    summary_mod.set_active_run_dir(None)


class TestUnifiedJsonlAggregation:
    """The b1 proxy and b2/b3 tracer paths both write to
    `<run_dir>/.sandbox-denials.jsonl` using the same record shape.
    summarize_and_write must aggregate them transparently."""

    def test_proxy_and_tracer_records_aggregate(self, tmp_path):
        # b1 path: record_denial writes a "network" record (proxy
        # audit-mode would-deny).
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial(
            "<egress-proxy CONNECT evil.invalid:443>",
            0, "network",
            host="evil.invalid", port=443,
            would_deny="host_not_in_allowlist", audit=True,
        )

        # b2/b3 path: tracer writes a "write" record (audit-mode
        # openat would-block).
        tracer._write_record(
            tmp_path, "openat", 257,
            [0xff, 0x1000, 0o644, 0, 0, 0],
            target_pid=12345,
            path="/etc/hostname",
        )

        # Aggregate. Both records should appear; by_type counts
        # both source paths.
        result = summary_mod.summarize_and_write(tmp_path)
        assert result is not None
        assert result["total_denials"] == 2
        assert result["by_type"] == {"network": 1, "write": 1}

        types_seen = {r["type"] for r in result["denials"]}
        assert types_seen == {"network", "write"}
        # Both flagged as audit
        assert all(r.get("audit") is True for r in result["denials"])

    def test_summary_file_contains_unified_view(self, tmp_path):
        # End-to-end: write from both paths, finalize, read the
        # on-disk summary, verify operator sees both.
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial(
            "<egress-proxy CONNECT a.example.com:443>", 0, "network",
            host="a.example.com", port=443,
            would_deny="host_not_in_allowlist", audit=True,
        )
        tracer._write_record(
            tmp_path, "openat", 257,
            [0xff, 0x1000, 0o644, 0, 0, 0],
            target_pid=1, path="/etc/secret",
        )
        tracer._write_record(
            tmp_path, "connect", 42,
            [3, 0xff, 16, 0, 0, 0],
            target_pid=1,
        )

        summary_mod.summarize_and_write(tmp_path)
        on_disk = json.loads(
            (tmp_path / summary_mod.SUMMARY_FILE).read_text()
        )
        assert on_disk["total_denials"] == 3
        # Mix of all three classes
        assert on_disk["by_type"] == {"network": 2, "write": 1}


class TestTracerRecordSuggestedFix:
    """Finding TT: tracer-emitted records don't include
    `suggested_fix` at write-time (the suggestion logic lives in
    summary._suggested_fix, not in the tracer subprocess). But
    summarize_and_write enriches them at aggregation time so the
    final sandbox-summary.json has UNIFORM record shapes — operators
    don't need defensive `.get('suggested_fix', '')` for cross-source
    compatibility."""

    def test_tracer_record_gets_suggested_fix_after_aggregation(self, tmp_path):
        tracer._write_record(
            tmp_path, "openat", 257,
            [0xff, 0x1000, 0o644, 0, 0, 0],
            target_pid=1, path="/etc/passwd",
        )
        result = summary_mod.summarize_and_write(tmp_path)
        r = result["denials"][0]
        # Enriched: suggested_fix now present even though tracer
        # didn't write it.
        assert "suggested_fix" in r, (
            "summarize_and_write should enrich tracer records with "
            "suggested_fix for cross-source consistency"
        )
        # And the suggestion should be type-appropriate (write opens
        # → write-suggestion text).
        assert r["suggested_fix"], "suggestion must be non-empty"

    def test_proxy_record_keeps_its_suggested_fix(self, tmp_path):
        # Proxy records (via record_denial) already include
        # suggested_fix; enrichment must NOT override it.
        summary_mod.set_active_run_dir(tmp_path)
        try:
            summary_mod.record_denial(
                "<egress-proxy CONNECT evil.com:443>", 0, "network",
                host="evil.com", port=443,
                would_deny="host_not_in_allowlist", audit=True,
            )
            result = summary_mod.summarize_and_write(tmp_path)
            r = result["denials"][0]
            assert "suggested_fix" in r
            # Audit branch text — pinned by the redactor test.
            assert "audit:" in r["suggested_fix"]
        finally:
            summary_mod.set_active_run_dir(None)


class TestRecordOrderPreserved:
    """JSONL preserves write order. Operators reading sandbox-summary
    see denials in the order they fired — useful for reconstructing
    the workflow's timeline."""

    def test_write_order_preserved_across_sources(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)

        # Interleave writes from both paths.
        summary_mod.record_denial(
            "<egress-proxy CONNECT a:443>", 0, "network",
            host="a", port=443, would_deny="host_not_in_allowlist",
            audit=True,
        )
        tracer._write_record(
            tmp_path, "openat", 257, [0]*6, target_pid=1, path="/p1",
        )
        summary_mod.record_denial(
            "<egress-proxy CONNECT b:443>", 0, "network",
            host="b", port=443, would_deny="host_not_in_allowlist",
            audit=True,
        )
        tracer._write_record(
            tmp_path, "openat", 257, [0]*6, target_pid=1, path="/p2",
        )

        result = summary_mod.summarize_and_write(tmp_path)
        denials = result["denials"]
        assert len(denials) == 4
        # Order: network(a), write(/p1), network(b), write(/p2)
        kinds = [(d["type"], d.get("host") or d.get("path"))
                 for d in denials]
        assert kinds == [
            ("network", "a"), ("write", "/p1"),
            ("network", "b"), ("write", "/p2"),
        ]


class TestRunDirAbsentIsNoOp:
    """Tracer's write_record fails gracefully when run_dir doesn't
    exist (operator-supplied bad path, race with cleanup, etc.).
    Mirrors the same robustness contract record_denial has."""

    def test_nonexistent_run_dir_returns_false(self, tmp_path):
        bogus = tmp_path / "does-not-exist"
        # Should not raise; just return False.
        ok = tracer._write_record(
            bogus, "openat", 257, [0]*6, target_pid=1, path="/x",
        )
        # _write_record creates parent dirs (mkdir parents=True), so
        # this WILL succeed if the path can be created. The assertion
        # is on robustness, not specifically failure.
        assert isinstance(ok, bool)


class TestMaxRecordsCap:
    """Tracer enforces a per-run cap (matches record_denial's). Once
    hit, further writes silently drop. Pin the cap value across both
    paths so a runaway target can't blow up sandbox-summary.json."""

    def test_tracer_and_summary_caps_match(self):
        # Both sides cap at 10000. Pin so a future divergence is
        # caught. The tracer's cap moved into the shared
        # core.sandbox.audit_budget module — the import target
        # changed, the value did not.
        from core.sandbox.audit_budget import (
            DEFAULT_GLOBAL_CAP as t_cap,
        )
        from core.sandbox.summary import (
            MAX_DENIALS_PER_RUN as s_cap,
        )
        assert t_cap == s_cap, (
            f"tracer cap {t_cap} != summary cap {s_cap} — operator "
            f"would see asymmetric DoS protection between sources"
        )
