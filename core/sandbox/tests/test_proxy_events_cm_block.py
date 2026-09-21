"""Regression tests for the context-manager-only proxy-event capture.

Pre-fix: ``with sandbox(use_egress_proxy=True, audit=True): http_calls()``
recorded ZERO events to ``proxy-events.jsonl`` because the proxy's
``register_sandbox`` happened only inside ``_run(cmd)`` per spawn. When
no subprocess was spawned through the sandbox's ``run`` (e.g. the
``packages/sca/agent.py`` pattern that wraps in-process ``analyse()``),
events from HTTPClient calls inside the with-block went unrecorded.

Post-fix: ``sandbox()`` registers a block-scoped proxy token at
``__enter__`` (gated on ``use_egress_proxy and _will_engage_audit and
output``) and drains + persists its events at ``__exit__``. Per-spawn
events that ALSO fanned into the block buffer get de-duped against
the cumulative ``_sandbox_events`` accumulator on
``(proxy_seq, t, host, port)`` so the single
``proxy-events.jsonl`` doesn't carry duplicates — the proxy-stamped
per-event ``proxy_seq`` keeps genuinely distinct events apart when
they tie on the timestamp key.

These tests pin the new behaviour without spinning up live network:
the proxy register/unregister API is exercised directly, and the
``_persist_proxy_events`` helper is tested in isolation for the
safe-open machinery.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux-only sandbox internals",
)

from core.sandbox import context as ctx                   # noqa: E402
from core.sandbox import proxy as proxy_mod               # noqa: E402
from core.sandbox.tests.capability import requires_landlock


class TestPersistProxyEventsHelper(unittest.TestCase):
    """Pin the contract of the hoisted ``_persist_proxy_events`` helper:
    empty inputs are no-ops, normal writes land in JSONL, the target-
    pollution skip honours an output-inside-target layout, and the
    safe-open path tolerates pre-existing FIFO / symlink planted by
    a hostile child."""

    def test_empty_events_is_noop(self):
        with TemporaryDirectory() as td:
            ctx._persist_proxy_events([], output=td)
            self.assertFalse(
                (Path(td) / proxy_mod.PROXY_EVENTS_FILENAME).exists()
            )

    def test_none_output_is_noop(self):
        events = [{"t": 1, "host": "a", "port": 443, "result": "allowed"}]
        # Doesn't raise, doesn't write anywhere.
        ctx._persist_proxy_events(events, output=None)

    def test_writes_jsonl(self):
        events = [
            {"t": 1.0, "host": "a", "port": 443, "result": "allowed"},
            {"t": 2.0, "host": "b", "port": 443, "result": "denied_host"},
        ]
        with TemporaryDirectory() as td:
            ctx._persist_proxy_events(events, output=td)
            log = Path(td) / proxy_mod.PROXY_EVENTS_FILENAME
            self.assertTrue(log.exists())
            lines = log.read_text().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["host"], "a")
            self.assertEqual(json.loads(lines[1])["result"], "denied_host")

    def test_target_pollution_skip(self):
        """When output lies inside target, the helper must not write —
        per the existing target-pollution invariant. In-memory events
        elsewhere are unaffected; the helper just declines to persist
        into the scanned tree."""
        events = [{"t": 1.0, "host": "a", "port": 443, "result": "allowed"}]
        with TemporaryDirectory() as td:
            target = Path(td) / "tree"
            target.mkdir()
            inside = target / "out"
            inside.mkdir()
            ctx._persist_proxy_events(
                events, output=str(inside), target=str(target),
            )
            self.assertFalse(
                (inside / proxy_mod.PROXY_EVENTS_FILENAME).exists()
            )

    def test_refuses_to_follow_symlink(self):
        """A hostile child could plant ``proxy-events.jsonl`` as a
        symlink to ``~/.ssh/authorized_keys``; the safe-open
        O_NOFOLLOW invariant must reject that path. The helper
        logs and skips — no exception escapes."""
        events = [{"t": 1.0, "host": "a", "port": 443, "result": "allowed"}]
        with TemporaryDirectory() as td:
            log_path = Path(td) / proxy_mod.PROXY_EVENTS_FILENAME
            target_file = Path(td) / "redirect-target"
            target_file.write_text("preexisting\n")
            os.symlink(target_file, log_path)

            ctx._persist_proxy_events(events, output=td)

            # The symlink target must NOT have grown — O_NOFOLLOW
            # rejected the open. The symlink itself is still there.
            self.assertEqual(target_file.read_text(), "preexisting\n")
            self.assertTrue(log_path.is_symlink())


@requires_landlock
class TestSandboxContextBlockEventCapture(unittest.TestCase):
    """Block-scoped token: ``sandbox(use_egress_proxy=True, audit=True,
    output=...)`` must register a token on the proxy at ``__enter__``
    so events from non-subprocess HTTPClient calls inside the
    with-block flow into a buffer that gets persisted at ``__exit__``.

    Drives the flow without live network by stubbing the proxy
    singleton with a fake that captures ``register_sandbox`` /
    ``unregister_sandbox`` calls. Asserts persistence happens with
    de-dup applied."""

    def _stub_proxy(self, recorded_events):
        """Return a fake proxy whose ``unregister_sandbox`` returns
        the supplied event list. Tracks ``register_sandbox`` /
        ``unregister_sandbox`` / ``acquire_audit_log_only`` /
        ``release_audit_log_only`` invocation order so the test can
        confirm the contract."""

        class _Fake:
            # Listening port the sandbox pins via Landlock's TCP
            # allowlist. The number doesn't matter under the test —
            # nothing actually connects — but the attribute must
            # exist because ``sandbox()`` reads it during setup.
            port = 18080

            def __init__(self):
                self.calls: list = []
                self._next_token = 0

            def register_sandbox(self, caller_label=None,
                                 lane_key=None,
                                 host_recon_threshold=None):
                self._next_token += 1
                self.calls.append(("register", caller_label, lane_key))
                return self._next_token

            def unregister_sandbox(self, token):
                self.calls.append(("unregister", token))
                return list(recorded_events)

            def acquire_audit_log_only(self):
                self.calls.append(("acquire_audit",))

            def release_audit_log_only(self):
                self.calls.append(("release_audit",))

            def add_hosts(self, hosts):
                pass

            # Lane surface: the Landlock-TCP tier now FAILS CLOSED
            # when the per-context lane cannot bind (no silent
            # fallback to the shared listener's union allowlist), so
            # the fake must provide a working lane like the real
            # proxy does.
            def bind_tcp_lane(self, *, label="sandbox",
                              allowed_hosts=None, allowed_ports=None):
                self.calls.append(("bind_tcp_lane", label))
                return 18081

            def close_tcp_lane(self, port):
                self.calls.append(("close_tcp_lane", port))

            def set_lane_audit(self, key, value):
                self.calls.append(("set_lane_audit", key, value))
                return True

            def update_idle_timeout(self, seconds):
                pass

        return _Fake()

    def test_block_token_registered_when_audit_engages(self):
        """``with sandbox(use_egress_proxy=True, audit=True,
        output=<dir>):`` must call ``register_sandbox`` with a
        ``:cm-block``-suffixed caller label so post-mortem readers
        can distinguish block events from per-spawn events."""
        recorded = [
            {"t": 1.0, "host": "api.osv.dev", "port": 443,
             "result": "allowed"},
        ]
        fake = self._stub_proxy(recorded)
        with TemporaryDirectory() as td:
            with patch.object(proxy_mod, "get_proxy",
                              return_value=fake):
                with ctx.sandbox(
                    target=td, output=td,
                    use_egress_proxy=True, proxy_hosts=["api.osv.dev"],
                    audit=True, audit_run_dir=td,
                    caller_label="test-cm-block",
                ):
                    pass

        # The block token must have been registered with the
        # ``:cm-block`` suffix, then unregistered at __exit__.
        register_calls = [c for c in fake.calls if c[0] == "register"]
        unregister_calls = [c for c in fake.calls if c[0] == "unregister"]
        self.assertGreaterEqual(len(register_calls), 1)
        block_label = next(
            (c[1] for c in register_calls
             if c[1] and c[1].endswith(":cm-block")), None,
        )
        self.assertIsNotNone(
            block_label,
            f"no :cm-block register call found in {fake.calls!r}",
        )
        self.assertEqual(block_label, "test-cm-block:cm-block")
        self.assertGreaterEqual(len(unregister_calls), 1)

    def test_block_events_persisted_to_jsonl(self):
        """Events returned by ``unregister_sandbox`` at __exit__
        land in ``<output>/proxy-events.jsonl`` with the safe-open
        path used by the per-spawn writer."""
        recorded = [
            {"t": 11.0, "host": "api.osv.dev", "port": 443,
             "result": "allowed"},
            {"t": 12.0, "host": "registry-1.docker.io", "port": 443,
             "result": "allowed"},
        ]
        fake = self._stub_proxy(recorded)
        # ``target`` and ``output`` MUST be separate dirs — if
        # ``output`` is inside ``target`` the helper's
        # target-pollution skip fires and no file is written
        # (covered by the dedicated test
        # ``test_target_pollution_skip`` above).
        with TemporaryDirectory() as td_target, \
                TemporaryDirectory() as td_out:
            with patch.object(proxy_mod, "get_proxy",
                              return_value=fake):
                with ctx.sandbox(
                    target=td_target, output=td_out,
                    use_egress_proxy=True,
                    proxy_hosts=["api.osv.dev", "registry-1.docker.io"],
                    audit=True, audit_run_dir=td_out,
                    caller_label="cm-test",
                ):
                    pass

            log = Path(td_out) / proxy_mod.PROXY_EVENTS_FILENAME
            self.assertTrue(
                log.exists(),
                f"proxy-events.jsonl missing in {td_out!r}; "
                f"calls={fake.calls!r}",
            )
            lines = log.read_text().splitlines()
            self.assertEqual(len(lines), 2)
            hosts = sorted(json.loads(line)["host"] for line in lines)
            self.assertEqual(hosts, [
                "api.osv.dev", "registry-1.docker.io",
            ])

    def test_block_token_not_registered_without_audit(self):
        """Without ``audit=True`` the block token must NOT be
        registered — keeping the persistence opt-in via the audit
        flag matches operator intent ("I asked for an audit log")."""
        fake = self._stub_proxy([])
        with TemporaryDirectory() as td:
            with patch.object(proxy_mod, "get_proxy",
                              return_value=fake):
                with ctx.sandbox(
                    target=td, output=td,
                    use_egress_proxy=True, proxy_hosts=["api.osv.dev"],
                    audit=False,
                    caller_label="no-audit",
                ):
                    pass
        register_calls = [c for c in fake.calls if c[0] == "register"]
        self.assertEqual(
            register_calls, [],
            "block token registered despite audit=False",
        )


# Same gate as TestSandboxContextBlockEventCapture above: the dedup is
# driven through a real ``ctx.sandbox`` engagement, whose target/output
# confinement needs a Landlock layer when the host refuses mount(2) at
# runtime — on the feature-matrix no-landlock/no-both lanes that shape
# hits the sandbox's designed fail-closed SandboxSetupError, which is
# the refusal contract working, not a dedup regression.
@requires_landlock
class TestBlockDrainDedupIdentity(unittest.TestCase):
    """The de-dup key is event IDENTITY (the proxy-stamped
    ``proxy_seq``), not the (t, host, port) coincidence key: two
    distinct events can tie on time.monotonic() + destination, and
    the old key silently dropped the second one from the persisted
    JSONL."""

    def _fake_proxy(self, block_events):
        outer = self

        class _Fake:
            port = 18080

            def __init__(self):
                self.calls: list = []
                self._next_token = 0

            def register_sandbox(self, caller_label=None,
                                 lane_key=None,
                                 host_recon_threshold=None):
                self._next_token += 1
                return self._next_token

            def unregister_sandbox(self, token):
                return [dict(e) for e in block_events]

            def acquire_audit_log_only(self):
                pass

            def release_audit_log_only(self):
                pass

            def add_hosts(self, hosts):
                pass

            def bind_tcp_lane(self, *, label="sandbox",
                              allowed_hosts=None, allowed_ports=None):
                return 18081

            def close_tcp_lane(self, port):
                pass

            def set_lane_audit(self, key, value):
                return True

            def update_idle_timeout(self, seconds):
                pass

        del outer
        return _Fake()

    def test_distinct_event_with_colliding_timestamp_key_persists(self):
        spawn_evt = {"proxy_seq": 1, "t": 5.0,
                     "host": "api.osv.dev",
                     "port": 443, "result": "allowed"}
        true_dup = dict(spawn_evt)
        distinct = {"proxy_seq": 2, "t": 5.0, "host": "api.osv.dev",
                    "port": 443, "result": "denied_host"}
        fake = self._fake_proxy([true_dup, distinct])
        with TemporaryDirectory() as td_target, \
                TemporaryDirectory() as td_out:
            with patch.object(proxy_mod, "get_proxy",
                              return_value=fake):
                with ctx.sandbox(
                    target=td_target, output=td_out,
                    use_egress_proxy=True, proxy_hosts=["api.osv.dev"],
                    audit=True, audit_run_dir=td_out,
                    caller_label="dedup-test",
                ) as run:
                    # Stand-in for a per-spawn drain: _run() extends
                    # the cumulative accumulator (exposed as
                    # run.events) with events it already persisted.
                    run.events.append(spawn_evt)

            log = Path(td_out) / proxy_mod.PROXY_EVENTS_FILENAME
            self.assertTrue(log.exists(), "block-only event not persisted")
            lines = [json.loads(x) for x in
                     log.read_text().splitlines()]
            # The true duplicate (same proxy_seq) is de-duped; the
            # distinct event with the colliding (t, host, port)
            # survives.
            self.assertEqual(
                [(e["proxy_seq"], e["result"]) for e in lines],
                [(2, "denied_host")],
            )


class TestProxyEventSeqStamp(unittest.TestCase):
    """The real proxy stamps a unique ``proxy_seq`` on every
    recorded event, and the SAME event fanned into several buffers
    keeps its one stamp through the unregister copies."""

    def test_distinct_events_get_distinct_seq_same_event_same_seq(self):
        proxy = proxy_mod.EgressProxy(allowed_hosts=set())
        try:
            tok_a = proxy.register_sandbox(caller_label="a")
            tok_b = proxy.register_sandbox(caller_label="b")
            shape = {"host": "h", "port": 443, "result": "allowed",
                     "reason": None, "resolved_ip": None,
                     "bytes_c2u": 0, "bytes_u2c": 0, "duration": 0.0}
            e1 = {"t": 5.0, **shape}
            e2 = {"t": 5.0, **shape}   # identical timestamp key
            proxy._record(e1)
            proxy._record(e2)
            ev_a = proxy.unregister_sandbox(tok_a)
            ev_b = proxy.unregister_sandbox(tok_b)
        finally:
            proxy.stop()
        seqs_a = [e["proxy_seq"] for e in ev_a]
        seqs_b = [e["proxy_seq"] for e in ev_b]
        self.assertEqual(len(set(seqs_a)), 2,
                         f"distinct events share a proxy_seq: {ev_a}")
        # Fan-out identity: each event carries the SAME seq in every
        # buffer copy.
        self.assertEqual(seqs_a, seqs_b)


if __name__ == "__main__":
    unittest.main()
