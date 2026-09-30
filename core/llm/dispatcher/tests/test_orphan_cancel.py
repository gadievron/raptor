"""Orphaned-upstream cancellation when the worker abandons a relay.

Pre-fix, a worker that timed out client-side abandoned its dispatcher
connection while the relay thread stayed blocked in the upstream dwell
(head wait or SSE inter-chunk gap); the death only surfaced at the
next WRITE — often minutes later — and the abandoned upstream
generation kept running (billed) with nobody to receive it. The
dispatcher now runs a per-relay orphan watcher that polls the
worker-side socket and, on death, tears the upstream connection down
(HTTP/1.x, via raw-socket shutdown — the one cross-thread action that
wakes a blocked read) and audits the abandonment as
``request.orphan_cancel``.

Hermetic — captive loopback upstream, raw-socket worker clients, no
LLM, no network.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import select
import socket
import threading
import time

import httpx
import pytest

import core.llm.dispatcher.server as dispatcher_server
from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import (
    _ORPHAN_POLL_INTERVAL_DEFAULT_S,
    _ORPHAN_POLL_INTERVAL_FLOOR_S,
    _TOKEN_HEADER,
    LLMDispatcher,
    _OrphanWatcher,
    _orphan_poll_interval_s,
    _worker_socket_dead,
)

_SSE_CHUNK_ONE = b"data: one\n\n"
_SSE_CHUNK_TWO = b"data: two\n\n"

# Injected orphan-poll grace window for the integration tests below
# (via the documented monkeypatch seam on _orphan_poll_interval_s —
# the env knob's >=1s floor is an anti-busy-poll guard on operator
# configuration, not a test bound; TestOrphanPollKnob still pins that
# contract and the slow-tier canary still runs the real env path).
# Both directions: TOO LOW and the detection-latency margins the
# tests assert (>=10 poll intervals of slack) drown in scheduler
# jitter under -n auto — 0.05s already assumes only tens-of-ms
# wakeup lag; TOO HIGH re-inserts the real-clock waits this seam
# exists to remove (every negative sleep below is expressed in poll
# multiples, so the whole file scales with this constant).
_FAST_POLL_S = 0.05


def _inject_fast_poll(
    monkeypatch: pytest.MonkeyPatch, interval_s: float = _FAST_POLL_S,
) -> None:
    monkeypatch.setattr(
        dispatcher_server, "_orphan_poll_interval_s", lambda: interval_s,
    )


def _chunked(payload: bytes) -> bytes:
    return b"%x\r\n%s\r\n" % (len(payload), payload)


class _CaptiveUpstream:
    """Raw-socket captive upstream whose dwell behaviour is the test
    subject. Modes:

    ``sse_stall``
        Chunked SSE head + one event, then wait up to ``stall_s`` for
        the connection to die (recording how long that took in
        ``disconnect_after_s`` / ``stall_outcome``); only on timeout
        send the second event + terminator.
    ``sse_slow_complete``
        Chunked SSE head + one event, sleep ``gap_s`` (longer than the
        watcher's poll interval), then the second event + terminator —
        the healthy slow upstream a live worker must receive intact.
    ``slow_head``
        Read the request, sleep ``head_delay_s`` before sending a
        complete Content-Length JSON response — the head-dwell shape.
    ``json_quick``
        Immediate complete Content-Length JSON response.
    """

    def __init__(
        self,
        mode: str,
        *,
        stall_s: float = 20.0,
        gap_s: float = 2.5,
        head_delay_s: float = 3.0,
    ) -> None:
        self.mode = mode
        self.stall_s = stall_s
        self.gap_s = gap_s
        self.head_delay_s = head_delay_s
        self.request_seen = threading.Event()
        self.disconnect_after_s: float | None = None
        self.stall_outcome: str | None = None

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.base_url = f"http://127.0.0.1:{self._listener.getsockname()[1]}"
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def shutdown(self) -> None:
        with contextlib.suppress(OSError):
            self._listener.close()

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _addr = self._listener.accept()
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(conn,), daemon=True,
            ).start()

    @staticmethod
    def _read_request(conn: socket.socket) -> bytes | None:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return None
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                length = int(value.strip())
        while len(rest) < length:
            chunk = conn.recv(65536)
            if not chunk:
                return None
            rest += chunk
        return head + b"\r\n\r\n" + rest

    def _handle(self, conn: socket.socket) -> None:
        try:
            if self._read_request(conn) is None:
                return
            self.request_seen.set()
            if self.mode in ("json_quick", "slow_head"):
                if self.mode == "slow_head":
                    time.sleep(self.head_delay_s)
                body = json.dumps({"ok": True}).encode()
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode()
                    + b"\r\n\r\n" + body,
                )
                return
            # SSE modes: chunked head + first event.
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/event-stream\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                + _chunked(_SSE_CHUNK_ONE),
            )
            if self.mode == "sse_slow_complete":
                time.sleep(self.gap_s)
                conn.sendall(_chunked(_SSE_CHUNK_TWO) + b"0\r\n\r\n")
                return
            # sse_stall: dwell, watching for the connection to die.
            start = time.monotonic()
            readable, _, _ = select.select([conn], [], [], self.stall_s)
            if readable:
                # EOF/RST from the dispatcher tearing us down.
                self.disconnect_after_s = time.monotonic() - start
                self.stall_outcome = "disconnect"
                return
            self.stall_outcome = "timeout"
            with contextlib.suppress(OSError):
                conn.sendall(_chunked(_SSE_CHUNK_TWO) + b"0\r\n\r\n")
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()


@pytest.fixture
def fake_creds() -> CredentialStore:
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "fake-anthropic-key",
        "openai": None,
        "gemini": None,
    }
    return creds


def _make_dispatcher(
    fake_creds: CredentialStore, tmp_path, upstream: _CaptiveUpstream,
) -> LLMDispatcher:
    d = LLMDispatcher(
        run_id="orphan-cancel", creds=fake_creds,
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600, token_budget=100,
    )
    original = d._rules["anthropic"]
    d._rules["anthropic"] = ProviderRule(
        name=original.name,
        upstream_base_url=upstream.base_url,
        inject_headers=original.inject_headers,
        strip_request_headers=original.strip_request_headers,
    )
    return d


def _worker_token(d: LLMDispatcher) -> str:
    _, fd = d.allocate_worker(label="test-worker")
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    return token


def _raw_worker_request(d: LLMDispatcher, token: str) -> socket.socket:
    """Speak HTTP over the worker UDS directly — the test needs exact
    control over WHEN the worker side abandons the connection."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect(str(d.socket_path))
    body = json.dumps({"model": "m", "messages": []}).encode()
    s.sendall(
        b"POST /anthropic/v1/messages HTTP/1.1\r\n"
        b"Host: dispatcher\r\n"
        + f"{_TOKEN_HEADER}: {token}\r\n".encode()
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body,
    )
    return s


def _recv_until(s: socket.socket, marker: bytes, timeout: float = 5.0) -> bytes:
    buf = b""
    deadline = time.monotonic() + timeout
    while marker not in buf and time.monotonic() < deadline:
        s.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            chunk = s.recv(65536)
        except TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _audit_events(d: LLMDispatcher, event: str) -> list[dict]:
    try:
        lines = d._audit_path.read_text().splitlines()
    except OSError:
        return []
    rows = [json.loads(line) for line in lines if line.strip()]
    return [r for r in rows if r.get("event") == event]


def _wait_audit(
    d: LLMDispatcher, event: str, timeout: float = 5.0,
) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = _audit_events(d, event)
        if rows:
            return rows
        time.sleep(0.05)
    return []


class TestWorkerSocketDead:
    """Unit coverage for the liveness probe on a real socketpair."""

    def test_silent_peer_is_alive(self):
        a, b = socket.socketpair()
        try:
            assert _worker_socket_dead(a) is False
        finally:
            a.close()
            b.close()

    def test_closed_peer_is_dead(self):
        a, b = socket.socketpair()
        try:
            b.close()
            assert _worker_socket_dead(a) is True
        finally:
            a.close()

    def test_peer_with_pending_data_is_alive(self):
        """Bytes after the request body are a protocol violation, but
        a live worker must NEVER be cancelled on suspicion — the
        write-time failure path owns misbehaviour."""
        a, b = socket.socketpair()
        try:
            b.sendall(b"unexpected")
            assert _worker_socket_dead(a) is False
            # The probe peeked, never consumed.
            assert b"unexpected" == a.recv(64, socket.MSG_PEEK)
        finally:
            a.close()
            b.close()

    def test_closed_own_fd_is_dead(self):
        a, b = socket.socketpair()
        a.close()
        b.close()
        assert _worker_socket_dead(a) is True


class TestOrphanPollKnob:

    def test_default_and_override(self, monkeypatch):
        monkeypatch.delenv(
            "RAPTOR_LLM_DISPATCHER_ORPHAN_POLL_S", raising=False,
        )
        assert _orphan_poll_interval_s() == _ORPHAN_POLL_INTERVAL_DEFAULT_S
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_ORPHAN_POLL_S", "7.5")
        assert _orphan_poll_interval_s() == 7.5

    def test_below_floor_falls_back_never_busy_polls(self, monkeypatch):
        """Direction 1: no configuration may busy-poll — sub-floor
        values fall back to the default."""
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_ORPHAN_POLL_S", "0.2")
        assert _orphan_poll_interval_s() == _ORPHAN_POLL_INTERVAL_DEFAULT_S
        assert _ORPHAN_POLL_INTERVAL_FLOOR_S >= 1.0

    def test_default_stays_useful(self):
        """Direction 2: the default must sit far below the ~100s-scale
        worker client timeout whose abandonments it exists to catch —
        a poll interval approaching that timeout would only rediscover
        the pre-fix write-time behaviour."""
        assert (
            _ORPHAN_POLL_INTERVAL_FLOOR_S
            <= _ORPHAN_POLL_INTERVAL_DEFAULT_S
            <= 30.0
        )

    @pytest.mark.parametrize("bad", ["nan", "inf", "-inf"])
    def test_non_finite_falls_back_never_busy_polls(self, monkeypatch, bad):
        """nan defeats the floor comparison (``nan < floor`` is False
        like every nan comparison) and would ride into
        ``Event.wait(nan)``, which returns immediately — a watcher
        thread busy-spinning at 100% CPU for the relay's whole
        upstream leg. inf passes the floor outright and never polls.
        Both must fall back to the (finite) default."""
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_ORPHAN_POLL_S", bad)
        got = _orphan_poll_interval_s()
        assert got == _ORPHAN_POLL_INTERVAL_DEFAULT_S
        assert math.isfinite(got)


class _FakeNetworkStream:
    def __init__(self, sock):
        self._sock = sock

    def get_extra_info(self, name):
        return self._sock if name == "socket" else None


class _FakeUpstreamResponse:
    """Just the two surfaces ``_cancel_upstream_locked`` touches:
    ``http_version`` and the ``network_stream`` extension."""

    def __init__(self, http_version, sock=None, with_stream=True):
        self.http_version = http_version
        self.extensions = (
            {"network_stream": _FakeNetworkStream(sock)}
            if with_stream else {}
        )


class TestCancelGuardIsStructural:
    """The h1-only guard on the raw-socket teardown is the ONLY thing
    standing between the watcher and killing innocent sibling streams
    multiplexed on a shared HTTP/2 connection. Pin it structurally:
    only an HTTP/1.x response with a reachable raw socket may be shut
    down; every other shape — h2 (even with a perfectly shootable
    socket attached), empty/missing version, head dwell, missing
    network stream — must stay flag-only with the socket untouched."""

    @contextlib.contextmanager
    def _watcher(self):
        a, b = socket.socketpair()
        # Interval far beyond the test's lifetime: the poll thread
        # never fires; the cancel routine is driven directly.
        w = _OrphanWatcher(a, 30.0, lambda cancel: None)
        try:
            yield w
        finally:
            w.stop()
            w.join()
            a.close()
            b.close()

    def _cancel(self, watcher, response):
        if response is not None:
            watcher.attach_response(response)
        with watcher._lock:
            return watcher._cancel_upstream_locked()

    def test_h1_with_socket_shuts_the_raw_socket(self):
        near, far = socket.socketpair()
        try:
            with self._watcher() as w:
                action = self._cancel(
                    w, _FakeUpstreamResponse("HTTP/1.1", near),
                )
            assert action == "upstream_shutdown"
            # The shutdown reached the actual socket: peer sees EOF.
            far.settimeout(2.0)
            assert far.recv(1) == b""
        finally:
            near.close()
            far.close()

    def test_h2_is_flag_only_and_socket_untouched(self):
        near, far = socket.socketpair()
        try:
            with self._watcher() as w:
                action = self._cancel(
                    w, _FakeUpstreamResponse("HTTP/2", near),
                )
            assert action == "flag_only"
            # No EOF on the peer — the socket was NOT shut down.
            far.settimeout(0.2)
            with pytest.raises(TimeoutError):
                far.recv(1)
        finally:
            near.close()
            far.close()

    def test_empty_version_is_flag_only(self):
        # Fail-safe: a version the guard cannot positively identify
        # as HTTP/1.x is treated like h2, never shot.
        near, far = socket.socketpair()
        try:
            with self._watcher() as w:
                assert self._cancel(
                    w, _FakeUpstreamResponse("", near),
                ) == "flag_only"
        finally:
            near.close()
            far.close()

    def test_head_dwell_no_response_is_flag_only(self):
        with self._watcher() as w:
            assert self._cancel(w, None) == "flag_only"

    def test_h1_without_network_stream_is_flag_only(self):
        with self._watcher() as w:
            assert self._cancel(
                w, _FakeUpstreamResponse("HTTP/1.1", with_stream=False),
            ) == "flag_only"


@pytest.mark.upstream_forward
class TestOrphanCancel:

    def _drive_disconnect_mid_stream(self, fake_creds, tmp_path) -> None:
        """Worker abandons after the first SSE event while the
        upstream stalls: the upstream connection must be torn down
        within the poll bound (not the 20s stall), with the
        abandonment audited and the error row tied to it. Poll
        interval is the caller's (injected fast path, or the real
        env-floor path for the slow-tier canary)."""
        upstream = _CaptiveUpstream("sse_stall", stall_s=20.0)
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            s = _raw_worker_request(d, token)
            assert _SSE_CHUNK_ONE in _recv_until(s, _SSE_CHUNK_ONE)
            s.close()  # the abandonment

            rows = _wait_audit(d, "request.orphan_cancel", timeout=6.0)
            assert rows
            row = rows[0]
            assert row["status"] == "ok"
            assert row["cancel"] == "upstream_shutdown"
            assert row["response_started"] is True
            assert isinstance(row["elapsed_s"], float)

            errors = _wait_audit(d, "request.error", timeout=6.0)
            assert errors
            assert errors[0]["worker_disconnected"] is True
            assert errors[0]["response_started"] is True

            # The upstream observed the teardown promptly — one poll
            # interval + scheduling slack, nowhere near its 20s stall.
            deadline = time.monotonic() + 6.0
            while (
                upstream.stall_outcome is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
            assert upstream.stall_outcome == "disconnect"
            assert upstream.disconnect_after_s is not None
            assert upstream.disconnect_after_s < 6.0
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_worker_disconnect_mid_stream_cancels_upstream(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        _inject_fast_poll(monkeypatch)
        self._drive_disconnect_mid_stream(fake_creds, tmp_path)

    @pytest.mark.slow
    def test_worker_disconnect_real_clock_canary(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """Real-clock canary for the injected-interval seam: the same
        abandonment teardown as
        test_worker_disconnect_mid_stream_cancels_upstream, but on the
        REAL env-knob path at its 1s anti-busy-poll floor — no
        monkeypatched accessor anywhere. Slow tier by design: the
        genuine grace window is the subject. If the fast battery is
        green while this reddens, suspect the seam itself (accessor
        rename, floor change, or grace behaviour that only holds for
        injected sub-second windows)."""
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_ORPHAN_POLL_S", "1")
        self._drive_disconnect_mid_stream(fake_creds, tmp_path)

    def test_healthy_slow_upstream_with_live_worker_is_untouched(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """An inter-chunk gap longer than the poll interval with a
        LIVE worker: several watcher polls run and none may misdetect
        — the stream completes intact, no orphan row, no error row."""
        _inject_fast_poll(monkeypatch)
        # Gap = 8 poll intervals (the original ran 2.5 intervals'
        # worth of polls mid-gap): MORE no-misdetect polls than
        # before, at a fraction of the wall clock.
        upstream = _CaptiveUpstream(
            "sse_slow_complete", gap_s=_FAST_POLL_S * 8,
        )
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            received = b""
            with httpx.Client(transport=transport, timeout=30.0) as client:
                with client.stream(
                    "POST", "http://_/anthropic/v1/messages",
                    headers={_TOKEN_HEADER: token},
                    content=json.dumps({"model": "m", "messages": []}),
                ) as resp:
                    assert resp.status_code == 200
                    for chunk in resp.iter_raw():
                        received += chunk
            assert _SSE_CHUNK_ONE in received
            assert _SSE_CHUNK_TWO in received
            assert _wait_audit(d, "request.dispatch", timeout=5.0)
            assert not _audit_events(d, "request.orphan_cancel")
            assert not _audit_events(d, "request.error")
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_worker_close_after_full_response_is_normal_completion(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """A worker that closes once it holds the complete response is
        a healthy close, never an orphan."""
        _inject_fast_poll(monkeypatch)
        upstream = _CaptiveUpstream("json_quick")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            s = _raw_worker_request(d, token)
            raw = _recv_until(s, b'{"ok": true}')
            assert b"200" in raw.split(b"\r\n", 1)[0]
            s.close()
            assert _wait_audit(d, "request.dispatch", timeout=5.0)
            # Give a poll interval a chance to misfire before checking
            # (three intervals — the original's 1.5-interval margin,
            # rounded up for scheduler jitter at the smaller scale).
            time.sleep(_FAST_POLL_S * 3)
            assert not _audit_events(d, "request.orphan_cancel")
            assert not _audit_events(d, "request.error")
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_worker_close_during_post_body_dwell_is_normal_completion(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """The load flake above, pinned deterministically: the relay
        thread can lose the CPU between relaying the last body byte
        and stopping the watcher (the final iterator advance sits
        inside that window).  Simulated by dwelling in the upstream
        iterator AFTER its final chunk, so several watcher polls run
        inside the window.  A worker that closes on the complete
        response there must still read as a healthy completion: the
        relay holds the final chunk back until the watcher is
        stopped, so the worker cannot observe completion while a
        poll could still classify its close as an abandonment."""
        _inject_fast_poll(monkeypatch)
        real_iter_raw = httpx.Response.iter_raw

        def _dwelling_iter_raw(resp, *args, **kwargs):
            yield from real_iter_raw(resp, *args, **kwargs)
            time.sleep(_FAST_POLL_S * 6)

        monkeypatch.setattr(
            httpx.Response, "iter_raw", _dwelling_iter_raw,
        )
        upstream = _CaptiveUpstream("json_quick")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            s = _raw_worker_request(d, token)
            raw = _recv_until(s, b'{"ok": true}')
            assert b"200" in raw.split(b"\r\n", 1)[0]
            s.close()
            assert _wait_audit(d, "request.dispatch", timeout=5.0)
            time.sleep(_FAST_POLL_S * 3)
            assert not _audit_events(d, "request.orphan_cancel")
            assert not _audit_events(d, "request.error")
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_final_chunk_is_held_until_watcher_stop_returns(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """Companion ordering pin for the dwell test above: the
        invariant is stop() happens-before the final chunk release,
        not merely "stop() runs near the drain".  Simulated by
        dwelling at the head of stop() itself, so polls keep running
        for several intervals after the relay decides to stop.  With
        the correct ordering the worker is still waiting on the held
        final chunk for the whole dwell — its close can only follow a
        completed stop().  Under the inverted ordering (final chunk
        written before stop()) the worker holds the complete body
        during the dwell, closes, and a still-live poll audits the
        healthy close as an orphan."""
        _inject_fast_poll(monkeypatch)
        real_stop = _OrphanWatcher.stop

        def _dwelling_stop(watcher_self):
            time.sleep(_FAST_POLL_S * 6)
            real_stop(watcher_self)

        monkeypatch.setattr(_OrphanWatcher, "stop", _dwelling_stop)
        upstream = _CaptiveUpstream("json_quick")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            s = _raw_worker_request(d, token)
            raw = _recv_until(s, b'{"ok": true}')
            assert b"200" in raw.split(b"\r\n", 1)[0]
            s.close()
            assert _wait_audit(d, "request.dispatch", timeout=5.0)
            time.sleep(_FAST_POLL_S * 3)
            assert not _audit_events(d, "request.orphan_cancel")
            assert not _audit_events(d, "request.error")
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_worker_disconnect_during_head_dwell_aborts_at_head(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """The honest residual, pinned: during the head dwell there is
        no response object to tear down (flag_only), but the flag is
        raised within the poll bound and the relay abandons the moment
        the head arrives instead of writing to a dead worker."""
        _inject_fast_poll(monkeypatch)
        # Head dwell = 20 poll intervals, detection budget = 12: the
        # budget-under-dwell ordering the assertion proves is kept
        # with MORE slack than the original (3s dwell / 2.5s budget
        # at a 1s poll) while the dwell itself shrinks 3x.
        head_delay_s = _FAST_POLL_S * 20
        upstream = _CaptiveUpstream("slow_head", head_delay_s=head_delay_s)
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            s = _raw_worker_request(d, token)
            # Close only after the request provably reached the
            # upstream, so the pre-upstream check cannot win the race
            # and the head dwell is the seam under test.
            assert upstream.request_seen.wait(5.0)
            s.close()

            rows = _wait_audit(
                d, "request.orphan_cancel", timeout=_FAST_POLL_S * 12,
            )
            assert rows, (
                f"detection must precede the {head_delay_s}s head arrival"
            )
            assert rows[0]["cancel"] == "flag_only"
            assert rows[0]["response_started"] is False

            errors = _wait_audit(d, "request.error", timeout=6.0)
            assert errors
            assert errors[0]["reason"] == "WorkerDisconnected"
            assert errors[0]["response_started"] is False
            assert errors[0]["worker_disconnected"] is True
        finally:
            upstream.shutdown()
            d.shutdown()


@pytest.mark.upstream_forward
class TestAcquireFailureRetiresWatcher:
    """The watcher thread starts before the shard acquire; an acquire
    that raises (the pool is closed in a shutdown race) exits the
    relay before its finally is armed. That path must stop the
    watcher — a leaked watcher reads the handler's own connection
    close as a worker abandonment and audits an orphan cancel for a
    relay that never opened an upstream."""

    @staticmethod
    def _live_watchers() -> list[threading.Thread]:
        return [
            t for t in threading.enumerate()
            if t.name == "llm-dispatcher-orphan-watch" and t.is_alive()
        ]

    def test_acquire_raise_stops_watcher_and_writes_no_orphan_row(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        _inject_fast_poll(monkeypatch)
        upstream = _CaptiveUpstream("json_quick")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            # Close the pool out from under the relay: the cached
            # shards object survives (same proxy env), so the relay's
            # acquire raises RuntimeError — the shutdown-race shape.
            d._upstream_client_shards().close()
            baseline = len(self._live_watchers())

            s = _raw_worker_request(d, token)
            # The relay dies before any upstream open; the handler
            # drops the connection without writing a response.
            assert _recv_until(s, b"HTTP/", timeout=3.0) == b""
            s.close()

            # The watcher must be retired on the failure path
            # (stopped + joined), not left to self-terminate.
            deadline = time.monotonic() + 5.0
            while (
                len(self._live_watchers()) > baseline
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
            assert len(self._live_watchers()) <= baseline

            # Give a leaked watcher's poll every chance to misfire —
            # two poll intervals on a connection the handler has
            # already closed (plus scheduler slack, the original's
            # 2.5s at a 1s poll) — before asserting audit silence.
            time.sleep(_FAST_POLL_S * 2 + 0.1)
            assert not _audit_events(d, "request.orphan_cancel")
        finally:
            upstream.shutdown()
            d.shutdown()


class TestWatcherAbortIsNotShardEvidence:
    """A watcher-induced abort — the dispatcher shut the upstream
    socket down itself because the WORKER left — is evidence about
    the worker, not the shard, even though it surfaces in the relay
    as a shard-health error class. At threshold 1 a single strike
    would drain and rebuild the shard, so the shard surviving pins
    the neutrality gate."""

    def test_watcher_cancel_does_not_drain_the_shard(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        _inject_fast_poll(monkeypatch)
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", "1")
        # One shard, so the relay under test provably rode the client
        # being asserted on.
        monkeypatch.delenv("RAPTOR_HTTP2", raising=False)
        monkeypatch.delenv("RAPTOR_HTTP2_SHARDS", raising=False)
        upstream = _CaptiveUpstream("sse_stall", stall_s=20.0)
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            shards = d._upstream_client_shards()
            assert len(shards.clients) == 1
            pooled = shards.clients[0]

            s = _raw_worker_request(d, token)
            assert _SSE_CHUNK_ONE in _recv_until(s, _SSE_CHUNK_ONE)
            s.close()  # abandonment → the watcher shuts the upstream

            errors = _wait_audit(d, "request.error", timeout=6.0)
            assert errors
            assert errors[0]["worker_disconnected"] is True
            # The relay returns its shard hold in its ``finally``,
            # which lags the error row by a scheduler beat — and a
            # drain (the failure this test pins as ABSENT) would
            # happen inside that release. Wait for the release itself
            # (every hold returned) under a bounded deadline instead
            # of a fixed beat, then pin: no drain, the shard client
            # is still in rotation.
            def _hold_returned() -> bool:
                return not any(shards.in_flight)

            deadline = time.monotonic() + 5.0
            while not _hold_returned() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert _hold_returned(), (
                "relay never returned its shard hold within the "
                f"deadline (in_flight={shards.in_flight})"
            )
            assert shards.clients[0] is pooled
            assert not pooled.is_closed
        finally:
            upstream.shutdown()
            d.shutdown()
