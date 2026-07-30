"""Tests for core.sandbox.triage — rules-based sandbox-telemetry triage."""

import json

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
        assert len(result["caveats"]) == 1
        assert "syscall-level attribution" in result["caveats"][0]

    def test_no_caveat_when_degraded_file_absent(self, tmp_path):
        _write_summary(tmp_path, [
            {"type": "write", "cmd": "x", "returncode": 1, "path": "/tmp/a"},
        ])
        result = triage_mod.triage_run(tmp_path)
        assert result["audit_degraded"] is False
        assert result["caveats"] == []

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
