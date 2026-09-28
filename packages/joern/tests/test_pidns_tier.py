"""JoernServer pid-namespace supervision tier: stamping, relaunch, ladder.

Everything here is hermetic — probes and Popen are patched, processes
are MagicMocks with pids beyond pid_max, and ``os.killpg`` is patched
to refuse where a stop path could reach it (the ``_safe_stop`` idiom
from test_server_uds). No namespaces, no JVM, no real process groups
(so nothing depends on ``getpgrp()``, which can be 0 on nested-pid-ns
runners).

The load-bearing directions:

* the tier stamp comes ONLY from the forwarder's achieved-tier report
  — never from the flag the server passed (a misstamped ``pidns``
  would skip the kill ladder with the safety net absent);
* a runtime refusal degrades to the group tier with exactly one
  relaunch, never a crash, never a loop;
* the group-kill ladder is demoted, not deleted: the group tier keeps
  it verbatim, the pidns tier consults it only as belt-and-braces
  after a stalled collapse.
"""

from __future__ import annotations

import logging
import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from packages.joern import server as server_mod
from packages.joern.netns_forwarder import (
    EXIT_PIDNS_UNSHARE_REFUSED,
    EXIT_PIDNS_WAITER_UNARMED,
)
from packages.joern.server import JoernServer


def _fake_proc(poll_rc: int | None = None) -> MagicMock:
    proc = MagicMock()
    proc.pid = 2_000_000_000  # inert: beyond pid_max
    proc.poll.return_value = poll_rc
    proc.stderr = MagicMock()
    proc.wait = MagicMock()
    return proc


def _run_start(
    srv: JoernServer,
    *,
    netns: bool = True,
    pidns: bool = True,
    procs: list[MagicMock],
    wait_ready: list[bool],
    tier_report: bytes | None = None,
) -> list[list[str]]:
    """Drive ``srv.start()`` under the tier-selection patch set.

    Returns one argv list per Popen call. ``tier_report`` (when set)
    is written to the inherited ready fd at spawn time, standing in
    for the forwarder's achieved-tier report.
    """
    argvs: list[list[str]] = []

    def fake_popen(cmd, **kwargs):
        argvs.append(list(cmd))
        if tier_report is not None and kwargs.get("pass_fds"):
            os.write(kwargs["pass_fds"][0], tier_report)
        return procs[len(argvs) - 1]

    with (
        patch("packages.joern.prereqs._java_version", return_value=21),
        patch("packages.joern.server._netns_isolation_available",
              return_value=netns),
        patch("packages.joern.server._pidns_supervision_available",
              return_value=pidns),
        patch("packages.joern.server._server_auth_supported",
              return_value=True),
        patch("packages.joern.server._repl_bridge_path",
              return_value="/opt/joern/repl-bridge"),
        patch("packages.joern.server.subprocess.Popen",
              side_effect=fake_popen),
        patch("packages.joern.server.os.killpg",
              side_effect=ProcessLookupError),
        patch.object(srv, "_wait_for_ready", side_effect=wait_ready),
        patch.object(srv, "_warmup_imports"),
    ):
        srv.start()
    return argvs


def _safe_stop(srv: JoernServer) -> None:
    with patch("packages.joern.server.os.killpg",
               side_effect=ProcessLookupError):
        srv.stop()


# ── achieved-tier report parsing ────────────────────────────────────


class TestReadAchievedTier:
    def _read(self, payload: bytes, *, close: bool = True,
              timeout_s: float = 5.0) -> str:
        r, w = os.pipe()
        try:
            if payload:
                os.write(w, payload)
            if close:
                os.close(w)
            return server_mod._read_achieved_tier(r, timeout_s=timeout_s)
        finally:
            os.close(r)
            if not close:
                os.close(w)

    def test_pidns_report_reads_pidns(self):
        assert self._read(b"supervision_tier=pidns\n") == "pidns"

    def test_group_report_reads_group(self):
        assert self._read(b"supervision_tier=group\n") == "group"

    def test_missing_report_reads_group(self):
        # Forwarder died (or a test double inherited nothing): EOF.
        assert self._read(b"") == "group"

    def test_garbled_report_reads_group(self):
        assert self._read(b"totally unrelated bytes\n") == "group"

    def test_prefixed_pidns_reads_group(self):
        # Only the EXACT report may stamp the strong tier.
        assert self._read(b"supervision_tier=pidnsX\n") == "group"

    def test_stalled_writer_times_out_to_group(self):
        # Write end open, no newline: bounded wait, weaker tier.
        assert self._read(b"supervision_tier=", close=False,
                          timeout_s=0.2) == "group"


# ── probe cache ─────────────────────────────────────────────────────


class TestPidnsProbeCache:
    def test_probe_result_cached(self, monkeypatch) -> None:
        monkeypatch.setattr(server_mod, "_PIDNS_PROBE_CACHE", None)
        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            proc = MagicMock()
            proc.returncode = 0
            proc.stderr = ""
            return proc

        with patch("packages.joern.server.subprocess.run",
                   side_effect=fake_run):
            assert server_mod._pidns_supervision_available() is True
            assert server_mod._pidns_supervision_available() is True
        assert len(calls) == 1
        assert calls[0][1].endswith("netns_forwarder.py")
        assert calls[0][2] == "--self-probe-pidns"

    def test_probe_failure_means_group_and_is_cached(self, monkeypatch):
        monkeypatch.setattr(server_mod, "_PIDNS_PROBE_CACHE", None)

        def fake_run(cmd, **kwargs):
            proc = MagicMock()
            proc.returncode = 1
            proc.stderr = "pidns self-probe failed: refused"
            return proc

        with patch("packages.joern.server.subprocess.run",
                   side_effect=fake_run):
            assert server_mod._pidns_supervision_available() is False
        assert server_mod._PIDNS_PROBE_CACHE is False

    def test_infra_failure_falls_back_without_caching(self, monkeypatch):
        # A probe that could not RUN is not a kernel verdict: fall
        # back for this boot, leave the cache open for the next one.
        monkeypatch.setattr(server_mod, "_PIDNS_PROBE_CACHE", None)
        with patch("packages.joern.server.subprocess.run",
                   side_effect=OSError("spawn refused")):
            assert server_mod._pidns_supervision_available() is False
        assert server_mod._PIDNS_PROBE_CACHE is None

    def test_invalidate_flips_a_positive_verdict(self, monkeypatch):
        monkeypatch.setattr(server_mod, "_PIDNS_PROBE_CACHE", True)
        server_mod._invalidate_pidns_probe()
        assert server_mod._PIDNS_PROBE_CACHE is False
        # And the flipped verdict is served without re-probing.
        with patch("packages.joern.server.subprocess.run") as run:
            assert server_mod._pidns_supervision_available() is False
        run.assert_not_called()

    def test_pidns_cache_is_separate_from_netns_cache(self, monkeypatch):
        # LSM policy commonly allows USER|NET while refusing NEWPID:
        # the verdicts must never share a cache slot.
        monkeypatch.setattr(server_mod, "_NETNS_PROBE_CACHE", True)
        monkeypatch.setattr(server_mod, "_PIDNS_PROBE_CACHE", False)
        assert server_mod._netns_isolation_available() is True
        assert server_mod._pidns_supervision_available() is False


# ── tier stamping at boot ───────────────────────────────────────────


class TestTierStamp:
    def test_positive_probe_puts_pidns_on_the_argv(self):
        srv = JoernServer()
        argvs = _run_start(srv, pidns=True, procs=[_fake_proc()],
                           wait_ready=[True])
        try:
            assert "--pidns" in argvs[0]
            assert "--ready-fd" in argvs[0]
        finally:
            _safe_stop(srv)

    def test_negative_probe_keeps_pidns_off_the_argv(self):
        srv = JoernServer()
        argvs = _run_start(srv, pidns=False, procs=[_fake_proc()],
                           wait_ready=[True])
        try:
            assert "--pidns" not in argvs[0]
            # The report channel exists on every netns boot — the
            # group tier reports too.
            assert "--ready-fd" in argvs[0]
            assert srv._supervision_tier == "group"
        finally:
            _safe_stop(srv)

    def test_requested_but_unreported_stamps_group(self):
        """Misstamp regression: --pidns was PASSED but no achieved-tier
        report ever arrived — the server must record the weaker tier,
        never the flag it requested."""
        srv = JoernServer()
        _run_start(srv, pidns=True, procs=[_fake_proc()],
                   wait_ready=[True], tier_report=None)
        try:
            assert srv._supervision_tier == "group"
        finally:
            _safe_stop(srv)

    def test_reported_pidns_stamps_pidns(self):
        srv = JoernServer()
        with patch("packages.joern.server._find_jvm_member") as find:
            _run_start(srv, pidns=True, procs=[_fake_proc()],
                       wait_ready=[True],
                       tier_report=b"supervision_tier=pidns\n")
        try:
            assert srv._supervision_tier == "pidns"
            assert srv._tier_refusal_reason is None
            # Strong tier never scans /proc for a member anchor.
            find.assert_not_called()
            assert srv._member_pid is None
        finally:
            _safe_stop(srv)

    def test_group_boot_derives_the_member_anchor(self):
        srv = JoernServer()
        with patch("packages.joern.server._find_jvm_member",
                   return_value=None) as find:
            _run_start(srv, pidns=False, procs=[_fake_proc()],
                       wait_ready=[True])
        try:
            find.assert_called_once()
        finally:
            _safe_stop(srv)

    def test_stop_clears_the_tier_stamp(self):
        srv = JoernServer()
        _run_start(srv, pidns=True, procs=[_fake_proc()],
                   wait_ready=[True],
                   tier_report=b"supervision_tier=pidns\n")
        assert srv._supervision_tier == "pidns"
        _safe_stop(srv)
        assert srv._supervision_tier == "group"
        assert srv._tier_refusal_reason is None


# ── runtime refusal → one relaunch, stamped Degraded ────────────────


class TestRuntimeRefusalRelaunch:
    @pytest.mark.parametrize(
        ("rc", "reason_fragment"),
        [
            (EXIT_PIDNS_UNSHARE_REFUSED, "refused at runtime"),
            (EXIT_PIDNS_WAITER_UNARMED, "failed to arm PDEATHSIG"),
        ],
    )
    def test_refusal_relaunches_once_without_pidns(
        self, monkeypatch, caplog, rc, reason_fragment,
    ):
        monkeypatch.setattr(server_mod, "_PIDNS_PROBE_CACHE", True)
        srv = JoernServer()
        with caplog.at_level(logging.WARNING,
                             logger="packages.joern.server"):
            argvs = _run_start(
                srv, pidns=True,
                procs=[_fake_proc(poll_rc=rc), _fake_proc()],
                wait_ready=[False, True],
            )
        try:
            assert len(argvs) == 2
            assert "--pidns" in argvs[0]
            assert "--pidns" not in argvs[1]
            # Same tuning attempt, not the flag-set retry: both boots
            # wrap joern in the forwarder with identical JVM flags.
            def jvm_flags(argv: list[str]) -> list[str]:
                tail = argv[argv.index("--") + 1:]
                return [f for f in tail if f.startswith("-X")]
            assert jvm_flags(argvs[0]) == jvm_flags(argvs[1])
            assert srv._supervision_tier == "group"
            assert srv._tier_refusal_reason is not None
            assert reason_fragment in srv._tier_refusal_reason
            # The cached probe verdict flipped: later boots in this
            # process pick the achievable tier directly.
            assert server_mod._PIDNS_PROBE_CACHE is False
            messages = " ".join(r.getMessage() for r in caplog.records)
            assert "DEGRADED to process-group tier" in messages
        finally:
            _safe_stop(srv)

    def test_refusal_cannot_relaunch_more_than_once(self, monkeypatch):
        """A persistently dying forwarder gets ONE tier relaunch, then
        the ordinary flag-set retry, then a hard failure — never an
        unbounded refusal loop."""
        monkeypatch.setattr(server_mod, "_PIDNS_PROBE_CACHE", True)
        srv = JoernServer()
        rc = EXIT_PIDNS_UNSHARE_REFUSED
        procs = [_fake_proc(poll_rc=rc) for _ in range(3)]
        with pytest.raises(RuntimeError, match="failed to start"):
            _run_start(srv, pidns=True, procs=procs,
                       wait_ready=[False, False, False])
        # Boot 1 (--pidns, refused) + relaunch (no --pidns) + one
        # flag-set retry: exactly three spawns, then the raise.
        assert all(p.poll.called for p in procs)

    def test_refusal_codes_without_pidns_are_not_special(self):
        """A JVM exiting with 97 on a boot that never passed --pidns
        rides the ordinary died-during-boot path (flag retry, then
        failure) — no tier relaunch, no probe invalidation."""
        srv = JoernServer()
        rc = EXIT_PIDNS_UNSHARE_REFUSED
        with (
            patch("packages.joern.server._invalidate_pidns_probe")
                as invalidate,
            pytest.raises(RuntimeError, match="failed to start"),
        ):
            _run_start(srv, pidns=False,
                       procs=[_fake_proc(poll_rc=rc),
                              _fake_proc(poll_rc=rc)],
                       wait_ready=[False, False])
        invalidate.assert_not_called()


# ── kill-ladder demotion (stop / stop_fast / restart) ───────────────


def _server_with_proc(tier: str) -> tuple[JoernServer, MagicMock]:
    srv = JoernServer()
    proc = _fake_proc()
    srv._proc = proc
    srv._pgid = proc.pid
    srv._supervision_tier = tier
    return srv, proc


class TestStopLadderDemotion:
    def test_group_tier_keeps_the_full_ladder(self):
        srv, proc = _server_with_proc("group")
        with (
            patch("packages.joern.server._ensure_group_dead",
                  return_value=True) as ensure,
            patch("packages.joern.server.os.killpg",
                  side_effect=ProcessLookupError),
        ):
            srv.stop()
        ensure.assert_called_once()
        proc.terminate.assert_called_once()  # killpg fallback path

    def test_pidns_tier_skips_the_ladder_on_a_clean_reap(self):
        srv, proc = _server_with_proc("pidns")
        proc.wait.return_value = 0
        with (
            patch("packages.joern.server._ensure_group_dead") as ensure,
            patch("packages.joern.server.os.killpg") as killpg,
        ):
            srv.stop()
        # The forwarder's reap IS the namespace-empty proof: no group
        # signalling, no /proc verification on the strong tier.
        ensure.assert_not_called()
        killpg.assert_not_called()
        proc.terminate.assert_called_once()

    def test_pidns_tier_stalled_collapse_falls_back_to_the_ladder(self):
        srv, proc = _server_with_proc("pidns")
        proc.wait.side_effect = subprocess.TimeoutExpired("joern", 5)
        with (
            patch("packages.joern.server._ensure_group_dead",
                  return_value=True) as ensure,
            patch("packages.joern.server._reap_in_background") as reap,
        ):
            srv.stop()
        proc.kill.assert_called_once()
        reap.assert_called_once()
        ensure.assert_called_once()  # belt-and-braces after the stall

    def test_pidns_tier_kill_path_survivor_stays_loud(self):
        # The SIGKILL path reaps only the leader; the namespace
        # collapse behind it is asynchronous. A member the group
        # probe still sees running must NOT be silently claimed
        # collapsed — the ladder (and its corroboration gate) is
        # consulted, exactly as the group tier would have been.
        srv, proc = _server_with_proc("pidns")
        proc.wait.side_effect = [subprocess.TimeoutExpired("joern", 5), 0]
        with (
            patch("packages.joern.server._ensure_group_dead",
                  return_value=False) as ensure,
            patch("packages.joern.server._pgid_alive",
                  return_value=True),
        ):
            srv.stop()
        proc.kill.assert_called_once()
        ensure.assert_called_once()

    def test_pidns_tier_kill_path_clean_probe_claims_proof(self):
        srv, proc = _server_with_proc("pidns")
        proc.wait.side_effect = [subprocess.TimeoutExpired("joern", 5), 0]
        with (
            patch("packages.joern.server._ensure_group_dead") as ensure,
            patch("packages.joern.server._pgid_alive",
                  return_value=False),
        ):
            srv.stop()
        proc.kill.assert_called_once()
        ensure.assert_not_called()


class TestStopFastLadderDemotion:
    def test_pidns_tier_single_verified_kill(self):
        srv, proc = _server_with_proc("pidns")
        proc.wait.return_value = 0
        with patch("packages.joern.server._ensure_group_dead") as ensure:
            assert srv.stop_fast() is True
        proc.kill.assert_called_once()
        ensure.assert_not_called()

    def test_pidns_tier_stalled_reap_goes_to_background(self):
        srv, proc = _server_with_proc("pidns")
        proc.wait.side_effect = subprocess.TimeoutExpired("joern", 3)
        with patch("packages.joern.server._reap_in_background") as reap:
            assert srv.stop_fast() is False
        reap.assert_called_once()

    def test_pidns_tier_surviving_member_reports_not_verified(self):
        # Leader reaped but the group probe still finds a running
        # member (asynchronous collapse stalled): the forced-exit
        # path must report the group NOT verified dead.
        srv, proc = _server_with_proc("pidns")
        proc.wait.return_value = 0
        with patch("packages.joern.server._pgid_alive",
                   return_value=True):
            assert srv.stop_fast() is False
        proc.kill.assert_called_once()

    def test_group_tier_routes_through_the_ladder(self):
        srv, proc = _server_with_proc("group")
        with patch("packages.joern.server._ensure_group_dead",
                   return_value=True) as ensure:
            assert srv.stop_fast() is True
        ensure.assert_called_once()
        proc.kill.assert_not_called()


class TestRestartSecondGraceWindow:
    def _restart(self, tier: str) -> MagicMock:
        srv, _proc = _server_with_proc(tier)
        with (
            patch.object(srv, "stop"),
            patch.object(srv, "start"),
            patch("packages.joern.lifecycle.note_server_replaced"),
            patch("packages.joern.server._ensure_group_dead",
                  return_value=True) as ensure,
        ):
            assert srv.restart() is True
        return ensure

    def test_group_tier_gets_the_second_grace_window(self):
        ensure = self._restart("group")
        ensure.assert_called_once()
        assert "restart" in ensure.call_args.kwargs["label"]

    def test_pidns_tier_skips_the_second_grace_window(self):
        ensure = self._restart("pidns")
        ensure.assert_not_called()
