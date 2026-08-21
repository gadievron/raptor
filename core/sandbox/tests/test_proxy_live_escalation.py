"""Tests for the egress-proxy's live stderr escalation banners.

Mirrors core.sandbox.tracer / seatbelt_audit's live escalation for the
two HIGH-severity network signals that are directly attributable at
the proxy layer:

  - denied_resolved_ip: gate 2 already BLOCKS these (see proxy.py's
    _ip_is_blocked) — this is escalation-only, no new blocking.
  - host_recon_pattern: distinct-denied-host count crossing the
    (profile-aware) threshold.

Pure-Python, no real network — exercises EgressProxy._record /
_live_escalate directly with synthetic events, same style as
test_proxy_perf.py.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


@pytest.fixture
def short_sock_dir():
    """A directory short enough that AF_UNIX socket paths fit
    sun_path (~104 bytes on macOS, 108 on Linux). pytest's
    ``tmp_path`` on CI runners can exceed that once a socket name is
    appended, making ``bind()`` fail with "AF_UNIX path too long" —
    derive socket paths from this fixture instead."""
    d = tempfile.mkdtemp(prefix="raptor-sk-", dir="/tmp")
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _denied_resolved_ip_event(resolved_ip="169.254.169.254", host="evil.example"):
    return {"host": host, "port": 443, "result": "denied_resolved_ip",
            "resolved_ip": resolved_ip, "reason": "resolved to blocked range"}


def _denied_host_event(host):
    return {"host": host, "port": 443, "result": "denied_host",
            "resolved_ip": None, "reason": "host not in allowlist"}


class TestResolvedIpEscalation:

    def test_denied_resolved_ip_escalates_immediately(
            self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy._record(_denied_resolved_ip_event())
            assert len(writes) == 1
            assert "169.254.169.254" in writes[0]
        finally:
            proxy.stop()

    def test_denied_resolved_ip_dedups_per_ip(self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy._record(_denied_resolved_ip_event(resolved_ip="169.254.169.254"))
            proxy._record(_denied_resolved_ip_event(resolved_ip="169.254.169.254"))
            assert len(writes) == 1, "dedup: one banner per resolved_ip per run"
            proxy._record(_denied_resolved_ip_event(resolved_ip="127.0.0.1"))
            assert len(writes) == 2, "a DIFFERENT resolved_ip still escalates"
        finally:
            proxy.stop()

    def test_allowed_events_never_escalate(self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy._record({"host": "x", "port": 443, "result": "allowed",
                           "resolved_ip": "1.2.3.4"})
            assert writes == []
        finally:
            proxy.stop()

    def test_escalation_disabled_by_env_var(
            self, reset_proxy, monkeypatch):
        monkeypatch.setenv("RAPTOR_SANDBOX_LIVE_ESCALATION_DISABLED", "1")
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy._record(_denied_resolved_ip_event())
            assert writes == []
        finally:
            proxy.stop()


class TestHostReconEscalation:
    # Live recon state is lane-scoped (mirroring _record's buffer
    # fan-out): counting happens per registered sandbox context. A
    # lane-less registration owns the run-global bucket; laned events
    # count toward their lane's bucket AND the run-global one.

    def test_escalates_once_at_threshold(self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        proxy.register_sandbox(host_recon_threshold=3)
        try:
            proxy._record(_denied_host_event("a.example"))
            assert writes == []
            proxy._record(_denied_host_event("b.example"))
            assert writes == []
            proxy._record(_denied_host_event("c.example"))
            assert len(writes) == 1, "threshold crossed on the 3rd distinct host"
            proxy._record(_denied_host_event("d.example"))
            assert len(writes) == 1, "one-shot: no re-escalation past threshold"
        finally:
            proxy.stop()

    def test_would_deny_host_also_counts(self, reset_proxy, monkeypatch):
        # would_deny_host (gate 1 audit-mode) is recon signal too, same
        # as denied_host (gate 1 enforce-mode) — same underlying
        # "target is probing hosts outside the allowlist" behaviour.
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        proxy.register_sandbox(host_recon_threshold=2)
        try:
            proxy._record({"host": "a.example", "result": "would_deny_host"})
            proxy._record({"host": "b.example", "result": "would_deny_host"})
            assert len(writes) == 1
        finally:
            proxy.stop()

    def test_repeated_same_host_does_not_inflate_count(
            self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        proxy.register_sandbox(host_recon_threshold=2)
        try:
            for _ in range(10):
                proxy._record(_denied_host_event("a.example"))
            assert writes == [], "one distinct host, threshold=2, never crosses"
        finally:
            proxy.stop()

    def test_register_sandbox_tightens_threshold_within_bucket(
            self, reset_proxy):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy.register_sandbox(host_recon_threshold=2)
            assert proxy._live_recon[None]["threshold"] == 2
            # A looser threshold from a second registration on the
            # SAME bucket must NOT weaken the already-tighter setting
            # (min-semantics within the bucket).
            proxy.register_sandbox(host_recon_threshold=10)
            assert proxy._live_recon[None]["threshold"] == 2
        finally:
            proxy.stop()

    def test_no_registration_no_live_counting(self, reset_proxy,
                                              monkeypatch):
        # Matches the buffer semantics: events outside any register/
        # unregister window aren't captured live; triage still sees
        # persisted events post-hoc.
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            for i in range(20):
                proxy._record(_denied_host_event(f"h{i}.example"))
            assert writes == []
        finally:
            proxy.stop()

    def test_unregister_tears_down_recon_state(self, reset_proxy,
                                               monkeypatch):
        # Sequential runs on the same proxy singleton must each start
        # from a clean distinct-host count — 2+1 hosts across two runs
        # is NOT recon at threshold 3.
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            token = proxy.register_sandbox(host_recon_threshold=3)
            proxy._record(_denied_host_event("a.example"))
            proxy._record(_denied_host_event("b.example"))
            proxy.unregister_sandbox(token)
            assert None not in proxy._live_recon

            proxy.register_sandbox(host_recon_threshold=3)
            proxy._record(_denied_host_event("c.example"))
            assert writes == [], "counts do not accumulate across runs"
        finally:
            proxy.stop()

    def test_refcounted_teardown_survives_sibling_unregister(
            self, reset_proxy, monkeypatch):
        # Two registrations share the run-global bucket (per-spawn +
        # cm-block pattern): the first unregister must not clear the
        # survivor's state.
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            t1 = proxy.register_sandbox(host_recon_threshold=3)
            proxy.register_sandbox(host_recon_threshold=3)
            proxy._record(_denied_host_event("a.example"))
            proxy._record(_denied_host_event("b.example"))
            proxy.unregister_sandbox(t1)
            proxy._record(_denied_host_event("c.example"))
            assert len(writes) == 1, "surviving registration still counts"
        finally:
            proxy.stop()

    def test_unknown_token_unregister_does_not_break_bucket(
            self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy.register_sandbox(host_recon_threshold=2)
            proxy.unregister_sandbox(999999)  # idempotent no-op
            proxy._record(_denied_host_event("a.example"))
            proxy._record(_denied_host_event("b.example"))
            assert len(writes) == 1
        finally:
            proxy.stop()


class TestEscalationNeverRaises:

    def test_stderr_write_failure_does_not_propagate(
            self, reset_proxy, monkeypatch):
        # Same layer tracer.py's mirror-image test targets
        # (test_escalation_never_raises_out_of_hot_path): os.write
        # itself fails, and _stderr_write's own try/except OSError
        # (see proxy.py) must swallow it before it reaches _record's
        # caller in the tunnel handler.
        def raising_write(fd, data):
            raise OSError("stderr closed")
        monkeypatch.setattr(proxy_mod.os, "write", raising_write)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy._record(_denied_resolved_ip_event())
        finally:
            proxy.stop()


class TestResolvedIpBannerCap:

    def test_banner_flood_capped_with_suppression_notice(
            self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            cap = proxy_mod._LIVE_RESOLVED_IP_BANNER_CAP
            # A DNS-rebinding target can mint unlimited distinct
            # resolved IPs — each attacker-paced. Well past the cap:
            for i in range(cap + 20):
                proxy._record(
                    _denied_resolved_ip_event(resolved_ip=f"10.9.0.{i}"))
            # cap per-IP banners + exactly one suppression notice.
            assert len(writes) == cap + 1
            assert "suppressed" in writes[-1]
            # Dedup-set memory is bounded at the cap too.
            assert len(proxy._live_resolved_ip_escalated) == cap
        finally:
            proxy.stop()

    def test_suppression_notice_fires_once(self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            cap = proxy_mod._LIVE_RESOLVED_IP_BANNER_CAP
            for i in range(cap + 1):
                proxy._record(
                    _denied_resolved_ip_event(resolved_ip=f"10.9.1.{i}"))
            n = len(writes)
            proxy._record(
                _denied_resolved_ip_event(resolved_ip="10.9.2.99"))
            assert len(writes) == n, "no further alerts past the notice"
        finally:
            proxy.stop()

    def test_banner_cap_resets_for_next_registered_run(
            self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            cap = proxy_mod._LIVE_RESOLVED_IP_BANNER_CAP
            first = proxy.register_sandbox(caller_label="run-a")
            for i in range(cap + 1):
                proxy._record(
                    _denied_resolved_ip_event(resolved_ip=f"10.9.3.{i}"))
            proxy.unregister_sandbox(first)
            assert len(writes) == cap + 1
            assert "suppressed" in writes[-1]

            second = proxy.register_sandbox(caller_label="run-b")
            proxy._record(
                _denied_resolved_ip_event(resolved_ip="10.9.4.1"))
            proxy.unregister_sandbox(second)
            assert len(writes) == cap + 2
            assert "10.9.4.1" in writes[-1]
        finally:
            proxy.stop()


class TestBannerSanitisation:

    def test_hostname_control_chars_escaped_in_banner(
            self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            # The hostname is attacker-controlled: a crafted name could
            # otherwise inject terminal escape sequences (ESC is ASCII,
            # so ascii/replace encoding alone does not strip it).
            proxy._record(_denied_resolved_ip_event(
                host="evil\x1b]0;pwned\x07.example"))
            assert len(writes) == 1
            assert "\x1b" not in writes[0]
            assert "\x07" not in writes[0]
            assert "\\x1b" in writes[0]
        finally:
            proxy.stop()

    def test_oversized_hostname_truncated_in_banner(
            self, reset_proxy, monkeypatch):
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy._record(_denied_resolved_ip_event(
                host="a" * 10_000 + ".example"))
            assert len(writes) == 1
            assert len(writes[0]) < 1_000
            assert "chars]" in writes[0], "explicit elision marker"
        finally:
            proxy.stop()


class TestEscalationKillSwitchParsing:

    def test_zero_value_does_not_disable(self, reset_proxy, monkeypatch):
        # =0 must mean "not disabled" — a bare bool(value) would treat
        # it as disabling a security notification.
        monkeypatch.setenv("RAPTOR_SANDBOX_LIVE_ESCALATION_DISABLED", "0")
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy._record(_denied_resolved_ip_event())
            assert len(writes) == 1
        finally:
            proxy.stop()

    @pytest.mark.parametrize("value", ["1", "true", "YES", " on "])
    def test_truthy_values_disable(self, reset_proxy, monkeypatch, value):
        monkeypatch.setenv("RAPTOR_SANDBOX_LIVE_ESCALATION_DISABLED", value)
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        try:
            proxy._record(_denied_resolved_ip_event())
            assert writes == []
        finally:
            proxy.stop()


class TestHostReconLaneIsolation:

    def test_concurrent_lanes_do_not_conflate(self, reset_proxy,
                                              monkeypatch,
                                              short_sock_dir):
        # Two concurrent runs each probing a couple of hosts must not
        # jointly trip a threshold neither reached alone.
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        path_a = str(short_sock_dir / "a.sock")
        path_b = str(short_sock_dir / "b.sock")
        try:
            proxy.bind_unix(path_a, label="run-a")
            proxy.bind_unix(path_b, label="run-b")
            proxy.register_sandbox(caller_label="run-a", lane_key=path_a,
                                   host_recon_threshold=3)
            proxy.register_sandbox(caller_label="run-b", lane_key=path_b,
                                   host_recon_threshold=3)
            lane_a = proxy._unix_lanes[path_a].lane_id
            lane_b = proxy._unix_lanes[path_b].lane_id

            for host in ("a1.example", "a2.example"):
                proxy._record({"host": host, "result": "denied_host",
                               "lane_id": lane_a})
            for host in ("b1.example", "b2.example"):
                proxy._record({"host": host, "result": "denied_host",
                               "lane_id": lane_b})
            assert writes == [], "2+2 across lanes is not 4 in one lane"

            proxy._record({"host": "a3.example", "result": "denied_host",
                           "lane_id": lane_a})
            assert len(writes) == 1, "lane A alone crossed its threshold"
        finally:
            proxy.stop()

    def test_laned_events_also_count_toward_global_bucket(
            self, reset_proxy, monkeypatch, short_sock_dir):
        # Over-capture direction, mirroring the buffer fan-out: a
        # lane-less registration sees the whole run.
        writes = []
        monkeypatch.setattr(proxy_mod, "_stderr_write",
                            lambda msg: writes.append(msg))
        proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
        path_a = str(short_sock_dir / "a.sock")
        try:
            proxy.bind_unix(path_a, label="run-a")
            proxy.register_sandbox(caller_label="global",
                                   host_recon_threshold=2)
            lane_a = proxy._unix_lanes[path_a].lane_id
            proxy._record({"host": "a1.example", "result": "denied_host",
                           "lane_id": lane_a})
            proxy._record({"host": "a2.example", "result": "denied_host",
                           "lane_id": lane_a})
            assert len(writes) == 1
        finally:
            proxy.stop()
