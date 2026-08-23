"""Tests for core.json.jsonl — the hardened append-only trail helpers.

Covers the substrate itself plus the hardening-consistency contract at
the three previously-divergent call sites (promotion-alarm,
reachability-suppression, audit-log): a symlink planted at the trail
path must be refused, not followed.
"""

import json
import os
from pathlib import Path

import pytest

from core.json import append_jsonl, load_jsonl


class TestAppendJsonl:

    def test_round_trip(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"a": 1})
        append_jsonl(p, {"b": [2, 3]})
        assert load_jsonl(p) == [{"a": 1}, {"b": [2, 3]}]

    def test_appends_not_truncates(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"first": True})
        append_jsonl(p, {"second": True})
        assert len(p.read_text().splitlines()) == 2

    def test_sort_keys(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"z": 1, "a": 2}, sort_keys=True)
        assert p.read_text() == '{"a": 2, "z": 1}\n'

    def test_compact(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"a": 1, "b": 2}, compact=True)
        assert p.read_text() == '{"a":1,"b":2}\n'

    def test_refuses_symlinked_path(self, tmp_path: Path):
        victim = tmp_path / "victim.txt"
        victim.write_text("do not touch\n")
        link = tmp_path / "trail.jsonl"
        link.symlink_to(victim)
        with pytest.raises(OSError):
            append_jsonl(link, {"evil": True})
        assert victim.read_text() == "do not touch\n"

    def test_raises_on_missing_parent(self, tmp_path: Path):
        with pytest.raises(OSError):
            append_jsonl(tmp_path / "no" / "such" / "dir.jsonl", {"a": 1})

    def test_non_serialisable_raises_typeerror(self, tmp_path: Path):
        with pytest.raises(TypeError):
            append_jsonl(tmp_path / "trail.jsonl", {"x": object()})

    def test_creates_with_requested_mode(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"a": 1}, mode=0o600)
        assert (p.stat().st_mode & 0o777) <= 0o600


class TestLoadJsonl:

    def test_missing_file(self, tmp_path: Path):
        assert load_jsonl(tmp_path / "absent.jsonl") == []

    def test_skips_blank_and_malformed_lines(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        p.write_text('{"ok": 1}\n\n{truncated\n{"ok": 2}\n')
        assert load_jsonl(p) == [{"ok": 1}, {"ok": 2}]

    def test_non_dict_records_preserved(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        p.write_text('[1, 2]\n"str"\n{"d": true}\n')
        assert load_jsonl(p) == [[1, 2], "str", {"d": True}]

    def test_refuses_symlinked_path(self, tmp_path: Path):
        real = tmp_path / "real.jsonl"
        real.write_text('{"a": 1}\n')
        link = tmp_path / "link.jsonl"
        link.symlink_to(real)
        assert load_jsonl(link) == []


class TestLoadJsonlBackends:
    """Line parsing must behave identically on both JSON backends."""

    def _both_backends(self):
        import core.json.utils as u
        backends = [("stdlib", None)]
        if u._orjson is not None:
            backends.append(("orjson", u._orjson))
        return u, backends

    def test_round_trip_both_backends(self, tmp_path: Path):
        u, backends = self._both_backends()
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"a": 1})
        append_jsonl(p, [1, "two", 3.5])
        for name, override in backends:
            saved = u._orjson
            try:
                u._orjson = override
                assert load_jsonl(p) == [{"a": 1}, [1, "two", 3.5]], name
            finally:
                u._orjson = saved

    def test_non_finite_line_skipped_both_backends(self, tmp_path: Path):
        """A NaN/Infinity line is malformed on BOTH backends — which
        records survive must not depend on which library is installed."""
        u, backends = self._both_backends()
        p = tmp_path / "trail.jsonl"
        p.write_text('{"ok": 1}\n{"bad": NaN}\n{"v": Infinity}\n{"ok": 2}\n')
        for name, override in backends:
            saved = u._orjson
            try:
                u._orjson = override
                assert load_jsonl(p) == [{"ok": 1}, {"ok": 2}], name
            finally:
                u._orjson = saved


class TestCallSiteHardeningConsistency:
    """The three previously-divergent trail writers all refuse symlinks."""

    def test_promotion_alarm_refuses_symlinked_trail(self, tmp_path: Path):
        from core.audit.promotion_alarm import ALARM_FILENAME, emit_alarm
        victim = tmp_path / "victim.txt"
        victim.write_text("")
        (tmp_path / ALARM_FILENAME).symlink_to(victim)
        # best-effort contract: swallowed, logged, victim untouched
        emit_alarm(tmp_path, {"event": "x", "file": "a", "function": "f",
                              "verdict": "finding", "evidence_tool": "",
                              "stage": "test"})
        assert victim.read_text() == ""

    def test_suppressions_refuses_symlinked_trail(self, tmp_path: Path):
        from core.analysis.reach_chokepoint import record_suppression
        victim = tmp_path / "victim.txt"
        victim.write_text("")
        (tmp_path / "suppressions.jsonl").symlink_to(victim)
        record_suppression(
            tmp_path, finding={"id": "F1"}, verdict="v", reason="r",
        )
        assert victim.read_text() == ""

    def test_audit_log_refuses_symlinked_trail(self, tmp_path: Path):
        from core.audit.record import append_audit_log
        victim = tmp_path / "victim.txt"
        victim.write_text("")
        (tmp_path / ".audit-log.jsonl").symlink_to(victim)
        with pytest.raises(OSError):
            append_audit_log(tmp_path, {"action": "x"})
        assert victim.read_text() == ""

    def test_audit_log_round_trip_unchanged(self, tmp_path: Path):
        from core.audit.record import append_audit_log, load_audit_log
        append_audit_log(tmp_path, {"action": "context", "n": 1})
        append_audit_log(tmp_path, {"action": "batch_flush"})
        recs = load_audit_log(tmp_path)
        assert recs == [{"action": "context", "n": 1},
                        {"action": "batch_flush"}]
        # compact separators preserved (telemetry-size parity)
        first = (tmp_path / ".audit-log.jsonl").read_text().splitlines()[0]
        assert first == '{"action":"context","n":1}'

    def test_suppression_record_shape_unchanged(self, tmp_path: Path):
        from core.analysis.reach_chokepoint import record_suppression
        record_suppression(
            tmp_path,
            finding={"finding_id": "F1", "rule_id": "R", "file_path": "a.c",
                     "line": 3, "function": "f"},
            verdict="binary_oracle_absent", reason="dead",
            extra={"tier": "full"},
        )
        rec = json.loads(
            (tmp_path / "suppressions.jsonl").read_text().splitlines()[0])
        assert rec == {
            "finding_id": "F1", "rule_id": "R", "file_path": "a.c",
            "line": 3, "function": "f", "verdict": "binary_oracle_absent",
            "reason": "dead", "dropped": True, "tier": "full",
        }

    def test_alarm_lines_key_stable(self, tmp_path: Path):
        from core.audit.promotion_alarm import ALARM_FILENAME, emit_alarm
        emit_alarm(tmp_path, {"z": 1, "a": 2, "file": "f", "function": "g",
                              "verdict": "finding", "evidence_tool": "",
                              "stage": "s"})
        line = (tmp_path / ALARM_FILENAME).read_text().splitlines()[0]
        keys = list(json.loads(line))
        assert keys == sorted(keys)


def test_lazy_reexport_surface():
    # NB: attribute access (not `is` against the top-of-file import) —
    # the f046 suite force-reimports core.json in-process, so module
    # object identity is not stable across test ordering.
    import core.json as cj
    assert "append_jsonl" in dir(cj)
    assert "load_jsonl" in dir(cj)
    assert callable(cj.append_jsonl)
    assert callable(cj.load_jsonl)
    assert "append_jsonl" in cj.__all__
    assert "load_jsonl" in cj.__all__


class TestLoadJsonlBudgets:
    """Byte budgets: fstat total gate before read, per-line skip."""

    def test_total_budget_oversize_loads_empty(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        for i in range(100):
            append_jsonl(p, {"i": i})
        assert load_jsonl(p, max_total_bytes=32) == []

    def test_total_budget_under_loads_all(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"a": 1})
        append_jsonl(p, {"b": 2})
        size = p.stat().st_size
        assert load_jsonl(p, max_total_bytes=size) == [{"a": 1}, {"b": 2}]

    def test_line_budget_skips_only_oversize(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"small": 1})
        append_jsonl(p, {"huge": "x" * 4096})
        append_jsonl(p, {"small": 2})
        assert load_jsonl(p, max_line_bytes=1024) == [
            {"small": 1}, {"small": 2},
        ]

    def test_default_unbounded_unchanged(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"huge": "x" * 4096})
        assert load_jsonl(p) == [{"huge": "x" * 4096}]

    def test_missing_file_with_budgets(self, tmp_path: Path):
        p = tmp_path / "absent.jsonl"
        assert load_jsonl(p, max_line_bytes=10, max_total_bytes=10) == []


def test_o_nofollow_available():
    # The hardening this module exists for requires O_NOFOLLOW on the
    # platforms RAPTOR supports (Linux/macOS).
    assert getattr(os, "O_NOFOLLOW", 0) != 0


class TestAppendNonFiniteParity:
    """Write/read parity: the reader skips NaN/Infinity lines as
    malformed, so the writer must refuse to emit them (allow_nan=False)
    instead of silently losing the record on the NEXT read."""

    def test_append_rejects_non_finite(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"ok": 1})
        for bad in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(ValueError):
                append_jsonl(p, {"score": bad})
        # Nothing was appended for the rejected records.
        assert load_jsonl(p) == [{"ok": 1}]

    def test_finite_floats_still_append(self, tmp_path: Path):
        p = tmp_path / "trail.jsonl"
        append_jsonl(p, {"score": 0.5})
        assert load_jsonl(p) == [{"score": 0.5}]
