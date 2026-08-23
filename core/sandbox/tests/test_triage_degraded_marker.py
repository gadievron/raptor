"""Audit-degradation signal must survive a hostile target.

Two halves, one property — "audit failed and there is no other
telemetry" must never silently read as "nothing happened":

1. Triage gate: a marker-only run dir (exactly what an unaudited
   fallback produces — no summary, no proxy events, only
   sandbox-audit-degraded.json) must yield a triage report carrying
   the degradation caveat, not None.

2. Marker persistence: the marker is written into the target-writable
   run root BEFORE the unaudited workload executes; the target can
   delete it. The parent knows it degraded, so run finalisation
   (summarize_and_write / triage_run) re-asserts the marker from
   parent memory, and a needed restore is itself tamper evidence.
"""

import json

import pytest

from core.sandbox import summary as summary_mod
from core.sandbox import triage as triage_mod


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """Fresh MAC key + fresh in-process degraded-marker registry."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(summary_mod, "_degraded_markers", {})
    yield


def _record_marker(run_dir, reason="log streamer failed to attach"):
    summary_mod.record_audit_degraded(
        run_dir, reason=reason,
        instructions="run without audit_mode on this host",
    )
    return run_dir / summary_mod.AUDIT_DEGRADED_FILE


class TestMarkerOnlyRunYieldsReport:
    """Half 1: the no-telemetry early return must consult the marker."""

    def test_marker_only_run_returns_report_not_none(self, tmp_path):
        _record_marker(tmp_path, reason="tracer unavailable")
        result = triage_mod.triage_run(tmp_path)
        assert result is not None
        assert result["audit_degraded"] is True
        assert any("tracer unavailable" in c for c in result["caveats"])
        assert (tmp_path / triage_mod.TRIAGE_FILE).exists()

    def test_marker_only_run_clean_verdict_with_caveat(self, tmp_path):
        _record_marker(tmp_path)
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_CLEAN
        assert result["signals"] == []

    def test_marker_only_lifecycle_failclosed_still_reports(self, tmp_path):
        # allow_legacy=False is the lifecycle posture; a MAC-stamped
        # marker written by the real API must verify and drive a report.
        _record_marker(tmp_path)
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result is not None
        assert result["audit_degraded"] is True
        assert result["inputs"]["integrity"]["audit_degraded"] == "verified"
        assert result["verdict"] == triage_mod.VERDICT_CLEAN

    def test_planted_unstamped_marker_only_flags_tampering(self, tmp_path):
        # A target planting an unstamped marker on an otherwise-empty
        # run must produce a tampering report, not silence and not a
        # trusted caveat.
        (tmp_path / summary_mod.AUDIT_DEGRADED_FILE).write_text(
            json.dumps({"degraded": True, "reason": "planted doubt"}))
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result is not None
        assert result["audit_degraded"] is False
        assert any(s["type"] == "telemetry_tampering"
                   for s in result["signals"])
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS

    def test_destroyed_marker_only_flags_tampering(self, tmp_path):
        # Marker replaced with garbage bytes: present-but-unreadable
        # must land in the tampered path, not the "no telemetry" path.
        (tmp_path / summary_mod.AUDIT_DEGRADED_FILE).write_bytes(
            b"\x00\xffnot json")
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result is not None
        assert any(s["type"] == "telemetry_tampering"
                   for s in result["signals"])

    def test_empty_dir_still_returns_none(self, tmp_path):
        assert triage_mod.triage_run(tmp_path) is None
        assert triage_mod.triage_run(tmp_path, allow_legacy=False) is None


class TestMarkerReassertion:
    """Half 2: a deleted marker must not stay deleted."""

    def test_deleted_marker_restored_by_summarize(self, tmp_path):
        marker = _record_marker(tmp_path)
        original = marker.read_bytes()
        marker.unlink()
        # summarize_and_write is the hook every terminal-state
        # transition runs — it must restore the marker even when it
        # goes on to return None (no denials recorded).
        assert summary_mod.summarize_and_write(tmp_path) is None
        assert marker.read_bytes() == original

    def test_deleted_marker_restored_by_triage(self, tmp_path):
        marker = _record_marker(tmp_path, reason="tracer unavailable")
        original = marker.read_bytes()
        marker.unlink()
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert marker.read_bytes() == original
        assert result is not None
        assert result["audit_degraded"] is True
        assert any("tracer unavailable" in c for c in result["caveats"])

    def test_restore_is_flagged_as_tampering(self, tmp_path):
        marker = _record_marker(tmp_path)
        marker.unlink()
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result["inputs"]["integrity"]["audit_degraded"] == "tampered"
        tamper = next(s for s in result["signals"]
                      if s["type"] == "telemetry_tampering")
        assert any("restored from parent memory" in e
                   for e in tamper["evidence"])
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS

    def test_restore_evidence_is_sticky_across_finalisation(self, tmp_path):
        # summarize_and_write repairs the file first; triage runs after
        # and must still see that a repair was necessary.
        marker = _record_marker(tmp_path)
        marker.unlink()
        summary_mod.summarize_and_write(tmp_path)
        assert marker.exists()
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result["inputs"]["integrity"]["audit_degraded"] == "tampered"
        assert any(s["type"] == "telemetry_tampering"
                   for s in result["signals"])

    def test_altered_marker_detected_and_restored(self, tmp_path):
        marker = _record_marker(tmp_path, reason="real reason")
        original = marker.read_bytes()
        forged = json.loads(original)
        forged["reason"] = "benign-looking excuse"
        marker.write_text(json.dumps(forged, indent=2) + "\n")
        assert summary_mod.reassert_audit_degraded(tmp_path) is True
        assert marker.read_bytes() == original

    def test_intact_marker_reassert_is_noop(self, tmp_path):
        marker = _record_marker(tmp_path)
        original = marker.read_bytes()
        assert summary_mod.reassert_audit_degraded(tmp_path) is False
        assert marker.read_bytes() == original
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert not any(s["type"] == "telemetry_tampering"
                       for s in result["signals"])

    def test_reassert_without_record_is_noop(self, tmp_path):
        assert summary_mod.reassert_audit_degraded(tmp_path) is False
        assert not (tmp_path / summary_mod.AUDIT_DEGRADED_FILE).exists()

    def test_restored_marker_still_mac_verifies(self, tmp_path):
        # The re-asserted payload is byte-identical to the original —
        # including its provenance token.
        marker = _record_marker(tmp_path)
        marker.unlink()
        summary_mod.reassert_audit_degraded(tmp_path)
        from core.sandbox import telemetry_mac
        payload = json.loads(marker.read_text())
        assert telemetry_mac.verify(
            telemetry_mac.audit_degraded_fields(
                payload, run=telemetry_mac.run_binding(tmp_path)),
            payload.get("mac"),
        )
