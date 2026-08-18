"""Tests for core.sandbox.triage — rules-based sandbox-telemetry triage."""

import json
import os

import pytest

from core.sandbox import summary as summary_mod
from core.sandbox import triage as triage_mod


def _write_summary(tmp_path, denials, total_denials=None):
    """Hand-write a sandbox-summary.json for cases the real writer API
    can't easily produce (specific syscall/marker permutations)."""
    payload = {
        "run_dir": str(tmp_path),
        "generated_at": "2026-07-23T00:00:00Z",
        "total_denials": total_denials if total_denials is not None else len(denials),
        "by_type": {},
        "denials": denials,
    }
    (tmp_path / summary_mod.SUMMARY_FILE).write_text(json.dumps(payload))


def _write_proxy_events(tmp_path, events):
    lines = "\n".join(json.dumps(e) for e in events)
    (tmp_path / triage_mod.PROXY_EVENTS_FILENAME).write_text(
        lines + ("\n" if lines else "")
    )


def _write_audit_degraded(tmp_path, reason="mount-ns unavailable"):
    payload = {
        "audit_requested": True,
        "audit_engaged": False,
        "degraded": True,
        "reason": reason,
        "instructions": "set kernel.apparmor_restrict_unprivileged_userns=0",
        "generated_at": "2026-07-23T00:00:00Z",
    }
    (tmp_path / summary_mod.AUDIT_DEGRADED_FILE).write_text(json.dumps(payload))


class TestMissingInput:
    def test_returns_none_when_neither_file_exists(self, tmp_path):
        assert triage_mod.triage_run(tmp_path) is None

    def test_writes_nothing_when_neither_file_exists(self, tmp_path):
        triage_mod.triage_run(tmp_path)
        assert not (tmp_path / triage_mod.TRIAGE_FILE).exists()


class TestVerdictClean:
    def test_clean_when_only_benign_write_denial(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "gcc -o out", "returncode": 1,
             "path": "/tmp/output.txt"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_CLEAN
        assert result["signals"] == []

    def test_clean_when_ordinary_network_denials_below_threshold(self, tmp_path):
        _write_proxy_events(tmp_path, [
            {"t": 1.0, "host": "evil.example.com", "port": 443,
             "result": "denied_host", "reason": "host not in allowlist",
             "resolved_ip": None},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_CLEAN
        assert result["signals"] == []


class TestEscapePrimitiveDenied:
    def test_fires_high_on_ptrace_syscall(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "some-tool", "returncode": 137,
             "syscall": "ptrace"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS
        signal = next(s for s in result["signals"]
                      if s["type"] == "escape_primitive_denied")
        assert signal["severity"] == "high"
        assert signal["evidence"] == ["ptrace"]

    def test_fires_on_bpf_and_io_uring_setup_combined(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "a", "returncode": 137, "syscall": "bpf"},
            {"type": "seccomp", "cmd": "b", "returncode": 137,
             "syscall": "io_uring_setup"},
        ])
        result = triage_mod.triage_run(tmp_path)
        signal = next(s for s in result["signals"]
                      if s["type"] == "escape_primitive_denied")
        assert signal["count"] == 2
        assert signal["evidence"] == ["bpf", "io_uring_setup"]

    def test_does_not_fire_on_non_escape_syscall(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "x", "returncode": 137, "syscall": "mount"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert not any(s["type"] == "escape_primitive_denied"
                        for s in result["signals"])


class TestSeccompUnattributed:
    def test_fires_low_when_no_syscall_field(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "make -j4", "returncode": 137,
             "profile": "full"},
        ])
        result = triage_mod.triage_run(tmp_path)
        signal = next(s for s in result["signals"]
                      if s["type"] == "seccomp_denied_unattributed")
        assert signal["severity"] == "low"

    def test_low_signal_alone_does_not_reach_suspicious(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "make -j4", "returncode": 137,
             "profile": "full"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_NOTABLE


class TestResolvedIpScreened:
    def test_single_occurrence_triggers_suspicious(self, tmp_path):
        _write_proxy_events(tmp_path, [
            {"t": 1.0, "host": "allowed.example.com", "port": 443,
             "result": "denied_resolved_ip", "reason": "resolved IP is private",
             "resolved_ip": "169.254.169.254"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS
        signal = next(s for s in result["signals"]
                      if s["type"] == "resolved_ip_screened")
        assert signal["count"] == 1
        assert signal["evidence"] == ["169.254.169.254"]

    def test_evidence_contains_resolved_ip(self, tmp_path):
        _write_proxy_events(tmp_path, [
            {"t": 1.0, "host": "a.example.com", "port": 443,
             "result": "denied_resolved_ip", "reason": "resolved IP is private",
             "resolved_ip": "10.0.0.5"},
        ])
        result = triage_mod.triage_run(tmp_path)
        signal = next(s for s in result["signals"]
                      if s["type"] == "resolved_ip_screened")
        assert "10.0.0.5" in signal["evidence"]


class TestHostReconPattern:
    def _events_for_hosts(self, hosts):
        return [
            {"t": float(i), "host": h, "port": 443, "result": "denied_host",
             "reason": "host not in allowlist", "resolved_ip": None}
            for i, h in enumerate(hosts)
        ]

    def test_below_threshold_no_signal(self, tmp_path):
        _write_proxy_events(tmp_path, self._events_for_hosts(
            ["a.com", "b.com", "c.com", "d.com"]))
        result = triage_mod.triage_run(tmp_path)
        assert not any(s["type"] == "host_recon_pattern"
                        for s in result["signals"])

    def test_at_threshold_fires_medium(self, tmp_path):
        _write_proxy_events(tmp_path, self._events_for_hosts(
            ["a.com", "b.com", "c.com", "d.com", "e.com"]))
        result = triage_mod.triage_run(tmp_path)
        signal = next(s for s in result["signals"]
                      if s["type"] == "host_recon_pattern")
        assert signal["severity"] == "medium"
        assert signal["count"] == 5

    def test_custom_threshold_param(self, tmp_path):
        _write_proxy_events(tmp_path, self._events_for_hosts(
            ["a.com", "b.com", "c.com"]))
        result = triage_mod.triage_run(tmp_path, host_recon_threshold=2)
        assert any(s["type"] == "host_recon_pattern" for s in result["signals"])


class TestProfileAwareHostReconThreshold:
    """host_recon_threshold=None (the default `_finalize_sandbox_triage`
    uses) resolves the threshold from whichever profile(s) the run's
    seccomp-type denial records were attributed to — see triage_run's
    docstring for the min-across-observed-profiles rationale."""

    def _events_for_hosts(self, hosts):
        return [
            {"t": float(i), "host": h, "port": 443, "result": "denied_host",
             "reason": "host not in allowlist", "resolved_ip": None}
            for i, h in enumerate(hosts)
        ]

    def test_no_profile_info_falls_back_to_flat_default(self, tmp_path):
        # No summary at all (only proxy events) — nothing to resolve a
        # profile from. Matches pre-existing behaviour: 3 hosts stays
        # below the flat DEFAULT_HOST_RECON_THRESHOLD (5).
        _write_proxy_events(tmp_path, self._events_for_hosts(
            ["a.com", "b.com", "c.com"]))
        result = triage_mod.triage_run(tmp_path)
        assert not any(s["type"] == "host_recon_pattern"
                        for s in result["signals"])

    def test_profile_override_tightens_threshold(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            triage_mod, "host_recon_threshold_for_profile",
            lambda profile, default: 2 if profile == "tight-profile" else default,
        )
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "x", "returncode": 1,
             "syscall": "ptrace", "profile": "tight-profile"},
        ])
        _write_proxy_events(tmp_path, self._events_for_hosts(
            ["a.com", "b.com", "c.com"]))
        result = triage_mod.triage_run(tmp_path)
        # 3 distinct hosts is below the flat default (5) but at/above
        # the profile-tightened threshold (2).
        assert any(s["type"] == "host_recon_pattern" for s in result["signals"])

    def test_multiple_profiles_uses_minimum(self, tmp_path, monkeypatch):
        thresholds = {"loose-profile": 10, "tight-profile": 2}
        monkeypatch.setattr(
            triage_mod, "host_recon_threshold_for_profile",
            lambda profile, default: thresholds.get(profile, default),
        )
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "x", "returncode": 1,
             "syscall": "ptrace", "profile": "loose-profile"},
            {"type": "seccomp", "cmd": "y", "returncode": 1,
             "syscall": "bpf", "profile": "tight-profile"},
        ])
        _write_proxy_events(tmp_path, self._events_for_hosts(
            ["a.com", "b.com", "c.com"]))
        result = triage_mod.triage_run(tmp_path)
        # Min(10, 2) = 2 governs — 3 distinct hosts crosses it, even
        # though the loose profile alone wouldn't.
        assert any(s["type"] == "host_recon_pattern" for s in result["signals"])

    def test_explicit_threshold_wins_over_profile_resolution(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            triage_mod, "host_recon_threshold_for_profile",
            lambda profile, default: 100,  # would suppress if consulted
        )
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "x", "returncode": 1,
             "syscall": "ptrace", "profile": "whatever"},
        ])
        _write_proxy_events(tmp_path, self._events_for_hosts(
            ["a.com", "b.com", "c.com"]))
        result = triage_mod.triage_run(tmp_path, host_recon_threshold=2)
        assert any(s["type"] == "host_recon_pattern" for s in result["signals"])


class TestCredentialPathTouch:
    def test_fires_high_on_ssh_path(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "cat", "returncode": 1,
             "path": "/root/.ssh/id_rsa"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS
        signal = next(s for s in result["signals"]
                      if s["type"] == "credential_path_touch")
        assert signal["severity"] == "high"

    def test_fires_on_aws_credentials(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "cat", "returncode": 1,
             "path": "/home/user/.aws/credentials"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert any(s["type"] == "credential_path_touch"
                    for s in result["signals"])

    def test_does_not_fire_on_unrelated_path(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "cat", "returncode": 1,
             "path": "/tmp/output.txt"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert not any(s["type"] == "credential_path_touch"
                        for s in result["signals"])


class TestVolumeAnomaly:
    def test_fires_when_total_denials_near_cap(self, tmp_path):
        near_cap = int(triage_mod.MAX_DENIALS_PER_RUN * 0.95)
        _write_summary(tmp_path, [
            {"type": "network", "cmd": "x", "returncode": 1},
        ], total_denials=near_cap)
        result = triage_mod.triage_run(tmp_path)
        signal = next(s for s in result["signals"]
                      if s["type"] == "volume_anomaly")
        assert signal["severity"] == "medium"

    def test_fires_on_category_budget_exceeded_marker(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "category_budget_exceeded", "audit": True,
             "category": "file-write", "cap": 3000},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert any(s["type"] == "volume_anomaly" for s in result["signals"])

    def test_fires_on_pid_budget_exceeded_marker(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "pid_budget_exceeded", "audit": True, "pid": 1234},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert any(s["type"] == "volume_anomaly" for s in result["signals"])

    def test_audit_summary_marker_alone_does_not_fire(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "audit_summary", "audit": True, "total_records": 10,
             "dropped_by_category": {}, "category_counts": {},
             "pid_counts": {}, "global_cap": 10000},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert not any(s["type"] == "volume_anomaly" for s in result["signals"])

    def test_budget_markers_excluded_from_enforcement_signals(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "pid_budget_exceeded", "audit": True, "pid": 1234},
            {"type": "category_budget_exceeded", "audit": True,
             "category": "network", "cap": 500},
        ])
        result = triage_mod.triage_run(tmp_path)
        fired_types = {s["type"] for s in result["signals"]}
        assert "escape_primitive_denied" not in fired_types
        assert "credential_path_touch" not in fired_types
        assert "seccomp_denied_unattributed" not in fired_types
        assert fired_types == {"volume_anomaly"}


class TestAuditDegradedCaveat:
    def test_caveat_present_when_degraded_file_exists(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "make", "returncode": 137,
             "profile": "full"},
        ])
        _write_audit_degraded(tmp_path)
        result = triage_mod.triage_run(tmp_path)
        assert result["audit_degraded"] is True
        # Hand-written (unstamped) fixtures also earn the legacy-
        # provenance caveat alongside the degraded-attribution one.
        assert any("syscall-level attribution" in c
                   for c in result["caveats"])

    def test_no_caveat_when_degraded_file_absent(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "x", "returncode": 1, "path": "/tmp/a"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["audit_degraded"] is False
        assert not any("syscall-level attribution" in c
                       for c in result["caveats"])

    def test_degraded_caveat_coexists_with_suspicious_verdict(self, tmp_path):
        _write_proxy_events(tmp_path, [
            {"t": 1.0, "host": "a.example.com", "port": 443,
             "result": "denied_resolved_ip", "reason": "resolved IP is private",
             "resolved_ip": "127.0.0.1"},
        ])
        _write_audit_degraded(tmp_path)
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS
        assert result["audit_degraded"] is True
        assert result["caveats"]


class TestVerdictDerivation:
    def test_any_high_severity_signal_yields_suspicious(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "x", "returncode": 1,
             "path": "/root/.ssh/id_rsa"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS

    def test_only_medium_low_signals_yields_notable(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "cmd": "x", "returncode": 137,
             "profile": "full"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_NOTABLE

    def test_no_signals_yields_clean(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "x", "returncode": 1, "path": "/tmp/a"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["verdict"] == triage_mod.VERDICT_CLEAN


class TestOutputWriting:
    def test_writes_sandbox_triage_json_to_run_dir(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "x", "returncode": 1, "path": "/tmp/a"},
        ])
        result = triage_mod.triage_run(tmp_path)
        triage_path = tmp_path / triage_mod.TRIAGE_FILE
        assert triage_path.exists()
        on_disk = json.loads(triage_path.read_text())
        assert on_disk == result

    def test_output_is_valid_json_indent_2(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "x", "returncode": 1, "path": "/tmp/a"},
        ])
        triage_mod.triage_run(tmp_path)
        text = (tmp_path / triage_mod.TRIAGE_FILE).read_text()
        assert text.startswith("{\n  ")
        json.loads(text)  # must parse cleanly


class TestCliMain:
    def test_cli_reports_clean_run(self, tmp_path, capsys):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "x", "returncode": 1, "path": "/tmp/a"},
        ])
        rc = triage_mod._cli_main([str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Clean" in out

    def test_cli_reports_no_telemetry_for_missing_input(self, tmp_path, capsys):
        rc = triage_mod._cli_main([str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "no sandbox telemetry found" in out

    def test_cli_errors_on_non_directory_arg(self, tmp_path, capsys):
        missing = tmp_path / "does-not-exist"
        rc = triage_mod._cli_main([str(missing)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "not a directory" in err

    def test_cli_exit_codes_reflect_verdict(self, tmp_path, capsys):
        # notable -> 3 (scriptable CI gate; suspicious -> 4 is pinned
        # by TestCliOutputSanitisation).
        _write_summary(tmp_path, [
            {"type": "seccomp", "profile": "full"},
        ])
        rc = triage_mod._cli_main([str(tmp_path)])
        assert rc == 3
        assert "Notable" in capsys.readouterr().out

    def test_cli_json_output(self, tmp_path, capsys):
        _write_summary(tmp_path, [
            {"type": "seccomp", "syscall": "ptrace", "profile": "full"},
        ])
        rc = triage_mod._cli_main([str(tmp_path), "--json"])
        assert rc == 4
        report = json.loads(capsys.readouterr().out)
        assert report["verdict"] == "suspicious"
        assert any(s["type"] == "escape_primitive_denied"
                   for s in report["signals"])


class TestEndToEndWithRealSummaryApi:
    @pytest.fixture(autouse=True)
    def _isolate_active_run(self):
        summary_mod.set_active_run_dir(None)
        yield
        summary_mod.set_active_run_dir(None)

    def test_triage_over_real_summarize_and_write_output(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial(
            "cat /root/.ssh/id_rsa", 1, "write", path="/root/.ssh/id_rsa",
        )
        summary_mod.summarize_and_write(tmp_path)

        result = triage_mod.triage_run(tmp_path)
        assert result is not None
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS
        assert any(s["type"] == "credential_path_touch"
                    for s in result["signals"])


class TestLifecycleIntegration:
    """End-to-end: start_run -> record_denial fires from _check_blocked ->
    complete_run/fail_run/cancel_run writes both sandbox-summary.json AND
    sandbox-triage.json. Verifies the auto-run wiring in
    core/run/metadata.py's _finalize_sandbox_triage (called right after
    _finalize_sandbox_summary in every terminal-state transition)."""

    @pytest.fixture(autouse=True)
    def _isolate_active_run(self):
        summary_mod.set_active_run_dir(None)
        yield
        summary_mod.set_active_run_dir(None)

    def test_complete_run_writes_triage_alongside_summary(self, tmp_path):
        from core.run.metadata import start_run, complete_run
        from core.sandbox.observe import _check_blocked

        run_dir = tmp_path / "agentic-20260723-150000-pid12345"
        start_run(run_dir, command="agentic")

        _check_blocked(
            stderr="cannot create '/root/.ssh/id_rsa': Permission denied\n",
            cmd_display="cat /root/.ssh/id_rsa",
            returncode=1,
            sandbox_info={},
            landlock_engaged=True,
        )

        complete_run(run_dir)

        summary_path = run_dir / summary_mod.SUMMARY_FILE
        triage_path = run_dir / triage_mod.TRIAGE_FILE
        assert summary_path.exists()
        assert triage_path.exists()

        on_disk = json.loads(triage_path.read_text())
        assert on_disk["verdict"] == triage_mod.VERDICT_SUSPICIOUS
        assert any(s["type"] == "credential_path_touch"
                    for s in on_disk["signals"])

    def test_failed_run_still_writes_triage(self, tmp_path):
        from core.run.metadata import start_run, fail_run
        from core.sandbox.observe import _check_blocked

        run_dir = tmp_path / "scan-failed"
        start_run(run_dir, command="scan")
        _check_blocked(
            stderr="Operation not permitted\n",
            cmd_display="weird-tool",
            returncode=137,
            sandbox_info={},
            seccomp_engaged=True,
            seccomp_profile="full",
        )
        fail_run(run_dir, error="something broke")

        triage_path = run_dir / triage_mod.TRIAGE_FILE
        assert triage_path.exists()
        on_disk = json.loads(triage_path.read_text())
        # Non-audit seccomp denial -> unattributed low-severity signal only.
        assert on_disk["verdict"] == triage_mod.VERDICT_NOTABLE

    def test_clean_run_writes_neither_summary_nor_triage(self, tmp_path):
        from core.run.metadata import start_run, complete_run

        run_dir = tmp_path / "scan-clean"
        start_run(run_dir, command="scan")
        # No denials recorded — nothing for either finalize step to act on.
        complete_run(run_dir)

        assert not (run_dir / summary_mod.SUMMARY_FILE).exists()
        assert not (run_dir / triage_mod.TRIAGE_FILE).exists()

    def test_triage_finalize_failure_does_not_break_lifecycle(
        self, tmp_path, monkeypatch,
    ):
        # Simulate triage_run raising — complete_run must still succeed
        # and flip status, mirroring _finalize_sandbox_summary's own
        # never-fail-the-lifecycle contract.
        from core.run.metadata import start_run, complete_run
        from core.sandbox.observe import _check_blocked

        run_dir = tmp_path / "agentic-broken-triage"
        start_run(run_dir, command="agentic")
        _check_blocked(
            stderr="curl: (7) Failed to connect to evil.com\n",
            cmd_display="curl evil.com",
            returncode=7,
            sandbox_info={},
            network_engaged=True,
        )

        def boom(*a, **k):
            raise RuntimeError("simulated triage crash")

        monkeypatch.setattr(triage_mod, "triage_run", boom)

        complete_run(run_dir)  # must not raise

        status = json.loads((run_dir / ".raptor-run.json").read_text())
        assert status["status"] == "completed"
        # Summary still wrote fine; triage failed silently.
        assert (run_dir / summary_mod.SUMMARY_FILE).exists()
        assert not (run_dir / triage_mod.TRIAGE_FILE).exists()


class TestEvidenceBounds:
    """Evidence values are attacker-controlled — bound list size and
    item length so a hostile target can't bloat sandbox-triage.json or
    stuff content into a report a human or LLM pass later reads."""

    def _events_for_hosts(self, hosts):
        return [
            {"t": float(i), "host": h, "port": 443, "result": "denied_host",
             "reason": "host not in allowlist", "resolved_ip": None}
            for i, h in enumerate(hosts)
        ]

    def test_host_recon_evidence_list_capped(self, tmp_path):
        n = triage_mod._MAX_EVIDENCE_ITEMS + 100
        _write_proxy_events(
            tmp_path, self._events_for_hosts([f"h{i:04d}.example"
                                              for i in range(n)]))
        result = triage_mod.triage_run(tmp_path)
        signal = next(s for s in result["signals"]
                      if s["type"] == "host_recon_pattern")
        # True count preserved; illustrative list capped with an
        # explicit elision marker (never masquerades as complete).
        assert signal["count"] == n
        assert len(signal["evidence"]) == triage_mod._MAX_EVIDENCE_ITEMS + 1
        assert signal["evidence"][-1] == "...[+100 more]"

    def test_oversized_evidence_item_truncated(self, tmp_path):
        long_path = "/home/x/.ssh/" + "A" * 5000
        _write_summary(tmp_path, [
            {"type": "landlock", "path": long_path, "profile": "full"},
        ])
        result = triage_mod.triage_run(tmp_path)
        signal = next(s for s in result["signals"]
                      if s["type"] == "credential_path_touch")
        item = signal["evidence"][0]
        assert len(item) < triage_mod._MAX_EVIDENCE_ITEM_LEN + 32
        assert item.endswith("chars]"), "explicit elision marker"

    def test_small_evidence_untouched(self, tmp_path):
        _write_proxy_events(tmp_path, self._events_for_hosts(
            ["a.com", "b.com", "c.com", "d.com", "e.com"]))
        result = triage_mod.triage_run(tmp_path)
        signal = next(s for s in result["signals"]
                      if s["type"] == "host_recon_pattern")
        assert signal["evidence"] == [
            "a.com", "b.com", "c.com", "d.com", "e.com"]


class TestCliOutputSanitisation:
    def test_caveat_with_control_chars_escaped(self, tmp_path, capsys):
        # The audit-degraded reason is read from a file inside the run
        # dir, which the sandboxed target may have write access to.
        _write_summary(tmp_path, [
            {"type": "seccomp", "syscall": "ptrace", "profile": "full"},
        ])
        _write_audit_degraded(tmp_path, reason="evil\x1b]0;pwned\x07reason")
        rc = triage_mod._cli_main([str(tmp_path)])
        assert rc == 4, "ptrace denial -> suspicious -> exit 4"
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "\\x1b" in out


class TestVerdictSurfacedInRunStatus:
    @pytest.fixture(autouse=True)
    def _isolate_active_run(self):
        summary_mod.set_active_run_dir(None)
        yield
        summary_mod.set_active_run_dir(None)

    def _run_with_denial(self, tmp_path, name):
        from core.run.metadata import start_run
        from core.sandbox.observe import _check_blocked

        run_dir = tmp_path / name
        start_run(run_dir, command="agentic")
        _check_blocked(
            stderr="cannot create '/root/.ssh/id_rsa': Permission denied\n",
            cmd_display="cat /root/.ssh/id_rsa",
            returncode=1,
            sandbox_info={},
            landlock_engaged=True,
        )
        return run_dir

    @staticmethod
    def _status(run_dir):
        return json.loads((run_dir / ".raptor-run.json").read_text())

    @classmethod
    def _extra(cls, run_dir):
        return cls._status(run_dir).get("extra", {})

    def test_complete_run_surfaces_verdict(self, tmp_path):
        from core.run.metadata import complete_run

        run_dir = self._run_with_denial(tmp_path, "r-complete")
        complete_run(run_dir)
        assert self._extra(run_dir)["sandbox_triage"] == "suspicious"

    def test_caller_extra_wins_on_conflict(self, tmp_path):
        from core.run.metadata import complete_run

        run_dir = self._run_with_denial(tmp_path, "r-conflict")
        complete_run(run_dir, extra={"sandbox_triage": "operator-override"})
        assert (self._extra(run_dir)["sandbox_triage"]
                == "operator-override")

    def test_clean_run_has_no_verdict_key(self, tmp_path):
        from core.run.metadata import complete_run, start_run

        run_dir = tmp_path / "r-clean"
        start_run(run_dir, command="scan")
        complete_run(run_dir)
        assert "sandbox_triage" not in self._extra(run_dir)

    def test_interrupt_run_writes_triage_and_verdict(self, tmp_path):
        from core.run.metadata import interrupt_run

        run_dir = self._run_with_denial(tmp_path, "r-interrupt")
        interrupt_run(run_dir, reason="supervisor drain")
        assert (run_dir / triage_mod.TRIAGE_FILE).exists()
        status = self._status(run_dir)
        assert status["status"] == "interrupted"
        assert status["extra"]["sandbox_triage"] == "suspicious"


class TestHostileSyscallArguments:
    def test_tiocsti_and_raw_socket_fire_high(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "syscall": "ioctl",
             "args": [0, 0x5412, 0, 0, 0, 0], "profile": "full"},
            {"type": "seccomp", "syscall": "socket",
             "args": [17, 3, 768, 0, 0, 0], "profile": "full"},
        ])
        result = triage_mod.triage_run(tmp_path)
        signal = next(s for s in result["signals"]
                      if s["type"] == "hostile_syscall_argument")
        assert signal["severity"] == "high"
        assert signal["evidence"] == [
            "ioctl(TIOCSTI)", "socket(AF_PACKET)"]
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS

    def test_af_unix_noise_does_not_fire(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "syscall": "socket",
             "args": [1, 1, 0, 0, 0, 0], "profile": "full"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert not any(s["type"] == "hostile_syscall_argument"
                       for s in result["signals"])

    def test_record_without_args_tolerated(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "syscall": "ioctl", "profile": "full"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert not any(s["type"] == "hostile_syscall_argument"
                       for s in result["signals"])


class TestTelemetryProvenance:
    """The run dir is target-writable during the run — triage verifies
    every input's provenance token before it may drive a verdict."""

    @pytest.fixture(autouse=True)
    def _isolated_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        yield

    @staticmethod
    def _stamped_event(event):
        from core.sandbox import telemetry_mac
        return {**event,
                "mac": telemetry_mac.mint(
                    telemetry_mac.proxy_event_fields(event))}

    def _denied_host(self, host):
        return {"t": 1.0, "host": host, "port": 443,
                "result": "denied_host", "reason": "not in allowlist",
                "resolved_ip": None}

    def test_stamped_stream_verifies_clean(self, tmp_path):
        _write_proxy_events(tmp_path, [
            self._stamped_event(self._denied_host(f"h{i}.example"))
            for i in range(5)
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["integrity"]["proxy_events"] == "verified"
        assert any(s["type"] == "host_recon_pattern"
                   for s in result["signals"])
        assert not any(s["type"] == "telemetry_tampering"
                       for s in result["signals"])

    def test_forged_line_in_stamped_stream_rejected_and_flagged(
            self, tmp_path):
        events = [self._stamped_event(self._denied_host(f"h{i}.example"))
                  for i in range(4)]
        # Target-appended line: no token. It must not be able to tip
        # host_recon over its threshold of 5 — and its presence in an
        # otherwise-stamped stream is itself the HIGH signal.
        events.append(self._denied_host("attacker-forged.example"))
        _write_proxy_events(tmp_path, events)
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["integrity"]["proxy_events"] == "tampered"
        assert not any(s["type"] == "host_recon_pattern"
                       for s in result["signals"])
        tamper = next(s for s in result["signals"]
                      if s["type"] == "telemetry_tampering")
        assert tamper["severity"] == "high"
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS

    def test_unstamped_stream_is_legacy_with_caveat(self, tmp_path):
        _write_proxy_events(tmp_path, [self._denied_host("a.example")])
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["integrity"]["proxy_events"] == "legacy"
        assert not any(s["type"] == "telemetry_tampering"
                       for s in result["signals"])
        assert any("provenance token" in c for c in result["caveats"])

    def test_planted_summary_dropped_and_flagged(self, tmp_path):
        # A pre-planted summary carrying a bogus token: its denials
        # must not reach the signal checks.
        _write_summary(tmp_path, [
            {"type": "seccomp", "syscall": "ptrace", "profile": "full"},
        ])
        import json as _json
        summary_path = tmp_path / summary_mod.SUMMARY_FILE
        payload = _json.loads(summary_path.read_text())
        payload["mac"] = "0" * 64
        summary_path.write_text(_json.dumps(payload))
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "tampered"
        assert not any(s["type"] == "escape_primitive_denied"
                       for s in result["signals"])
        assert any(s["type"] == "telemetry_tampering"
                   for s in result["signals"])

    def test_real_summary_writer_roundtrips_verified(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        try:
            summary_mod.record_denial(
                "cat /root/.ssh/id_rsa", 1, "write",
                path="/root/.ssh/id_rsa")
            summary_mod.summarize_and_write(tmp_path)
        finally:
            summary_mod.set_active_run_dir(None)
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "verified"
        assert result["verdict"] == triage_mod.VERDICT_SUSPICIOUS
        assert not any("provenance token" in c for c in result["caveats"])

    def test_forged_audit_degraded_marker_ignored(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "seccomp", "syscall": "ptrace", "profile": "full"},
        ])
        import json as _json
        marker = {"audit_requested": True, "audit_engaged": False,
                  "degraded": True, "reason": "planted doubt",
                  "instructions": "", "mac": "0" * 64,
                  "generated_at": "2026-07-23T00:00:00Z"}
        (tmp_path / summary_mod.AUDIT_DEGRADED_FILE).write_text(
            _json.dumps(marker))
        result = triage_mod.triage_run(tmp_path)
        assert result["audit_degraded"] is False
        assert not any("planted doubt" in c for c in result["caveats"])
        assert any(s["type"] == "telemetry_tampering"
                   for s in result["signals"])

    def test_report_self_stamp_roundtrips(self, tmp_path):
        _write_proxy_events(tmp_path, [self._denied_host("a.example")])
        triage_mod.triage_run(tmp_path)
        import json as _json
        on_disk = _json.loads(
            (tmp_path / triage_mod.TRIAGE_FILE).read_text())
        assert triage_mod.verify_triage_report(on_disk) == "verified"
        on_disk["verdict"] = "suspicious"  # launder a verdict upward/downward
        assert triage_mod.verify_triage_report(on_disk) == "tampered"
        del on_disk["mac"]
        assert triage_mod.verify_triage_report(on_disk) == "legacy"


class TestHostileArtifactReads:
    """The run dir is target-writable: triage's readers must survive
    planted FIFOs (lifecycle hang), symlinks (boundary escape), and
    oversized files (memory lever) — same discipline as the writers."""

    def test_planted_fifo_does_not_hang_lifecycle(self, tmp_path):
        os.mkfifo(tmp_path / summary_mod.SUMMARY_FILE)
        _write_proxy_events(tmp_path, [
            {"t": 1.0, "host": "a.example", "port": 443,
             "result": "denied_host", "reason": "x", "resolved_ip": None},
        ])
        # A plain open() would block forever on a writerless FIFO —
        # this call returning at all is the assertion; a wall-clock
        # guard would only turn a hang into a slow failure.
        result = triage_mod.triage_run(tmp_path)
        assert result is not None
        assert result["inputs"]["sandbox_summary_present"] is False

    def test_planted_symlink_not_followed(self, tmp_path):
        secret = tmp_path / "outside" / "secret.json"
        secret.parent.mkdir()
        secret.write_text('{"denials": [], "total_denials": 0}')
        os.symlink(secret, tmp_path / summary_mod.SUMMARY_FILE)
        _write_proxy_events(tmp_path, [
            {"t": 1.0, "host": "a.example", "port": 443,
             "result": "denied_host", "reason": "x", "resolved_ip": None},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["sandbox_summary_present"] is False

    def test_oversized_planted_file_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(triage_mod, "_MAX_INPUT_BYTES", 4096)
        (tmp_path / summary_mod.SUMMARY_FILE).write_text(
            '{"denials": [' + '"x",' * 5000 + '"x"]}')
        _write_proxy_events(tmp_path, [
            {"t": 1.0, "host": "a.example", "port": 443,
             "result": "denied_host", "reason": "x", "resolved_ip": None},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["sandbox_summary_present"] is False

    def test_non_dict_json_refused(self, tmp_path):
        (tmp_path / summary_mod.SUMMARY_FILE).write_text('["not", "a", "dict"]')
        _write_proxy_events(tmp_path, [
            {"t": 1.0, "host": "a.example", "port": 443,
             "result": "denied_host", "reason": "x", "resolved_ip": None},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["sandbox_summary_present"] is False
