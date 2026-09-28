"""Stall watchdog for streaming relays.

A silently wedged upstream tunnel (no FIN/RST — reads simply never
complete) used to hold a streaming relay for the FULL upstream read
timeout (600s default) before anything noticed. httpx's read timeout
bounds each individual read operation, so on an SSE relay it is the
inter-chunk gap detector: streaming requests now ride a much tighter
per-read window (``RAPTOR_LLM_DISPATCHER_STREAM_STALL_S``, default
120s) while non-streaming requests keep the full timeout — their one
body read legitimately spans the whole generation. A trip surfaces
as ``httpx.ReadTimeout`` on the existing abort paths and is
deliberately NOT eligible for the transparent stale-reuse retry (the
request may be mid-generation upstream; re-sending double-bills).

Hermetic — captive loopback upstream, no LLM, no network.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import threading
import time

import httpx
import pytest

from core.llm.dispatcher import server as dispatcher_server
from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import (
    _STALE_REUSE_ERRORS,
    _STREAM_STALL_DEFAULT_S,
    _STREAM_STALL_FLOOR_S,
    _TOKEN_HEADER,
    _UPSTREAM_CONNECT_TIMEOUT_S,
    _UPSTREAM_DEFAULT_TIMEOUT_S,
    LLMDispatcher,
    _OrphanWatcher,
    _request_wants_stream,
    _stream_stall_s,
    _upstream_timeout_for,
)

_STALL_ENV = "RAPTOR_LLM_DISPATCHER_STREAM_STALL_S"
_SSE_CHUNK_ONE = b"data: one\n\n"


def _chunked(payload: bytes) -> bytes:
    return b"%x\r\n%s\r\n" % (len(payload), payload)


class _WedgedUpstream:
    """Captive upstream that accepts, reads the request, then wedges:
    either before the response head (``head_wedge``) or after the SSE
    head + one event (``sse_wedge``). Never sends FIN — the exact
    silent-tunnel shape the watchdog exists to detect. Counts
    connections so retry exclusion is provable."""

    def __init__(self, mode: str, wedge_s: float = 30.0) -> None:
        self.mode = mode
        self.wedge_s = wedge_s
        self.connections = 0
        self._lock = threading.Lock()
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
            with self._lock:
                self.connections += 1
            threading.Thread(
                target=self._handle, args=(conn,), daemon=True,
            ).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    return
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
                    return
                rest += chunk
            if self.mode == "sse_wedge":
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/event-stream\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n"
                    + _chunked(_SSE_CHUNK_ONE),
                )
            # Wedge: hold the connection open, send nothing more.
            time.sleep(self.wedge_s)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()


@pytest.fixture(autouse=True)
def _default_timeout_env(monkeypatch):
    # Hermetic: the surrounding environment may tune the upstream
    # timeout; these tests pin behaviour against the defaults.
    monkeypatch.delenv(
        "RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S", raising=False,
    )


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
    fake_creds: CredentialStore, tmp_path, upstream: _WedgedUpstream,
) -> LLMDispatcher:
    d = LLMDispatcher(
        run_id="stall-watchdog", creds=fake_creds,
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


def _audit_events(d: LLMDispatcher, event: str) -> list[dict]:
    try:
        lines = d._audit_path.read_text().splitlines()
    except OSError:
        return []
    rows = [json.loads(line) for line in lines if line.strip()]
    return [r for r in rows if r.get("event") == event]


def _wait_audit(
    d: LLMDispatcher, event: str, timeout: float = 10.0,
) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = _audit_events(d, event)
        if rows:
            return rows
        time.sleep(0.05)
    return []


_STREAMING_BODY = json.dumps(
    {"model": "m", "stream": True, "messages": []},
).encode()
_PLAIN_BODY = json.dumps({"model": "m", "messages": []}).encode()


class TestStallKnob:

    def test_default_and_override(self, monkeypatch):
        monkeypatch.delenv(_STALL_ENV, raising=False)
        assert _stream_stall_s() == _STREAM_STALL_DEFAULT_S
        monkeypatch.setenv(_STALL_ENV, "45")
        assert _stream_stall_s() == 45.0

    def test_below_floor_falls_back(self, monkeypatch):
        # Direction 1: a sub-floor window is indistinguishable from
        # normal SSE event pacing — it would abort healthy streams.
        monkeypatch.setenv(_STALL_ENV, "0.5")
        assert _stream_stall_s() == _STREAM_STALL_DEFAULT_S

    def test_garbage_falls_back(self, monkeypatch):
        monkeypatch.setenv(_STALL_ENV, "soon")
        assert _stream_stall_s() == _STREAM_STALL_DEFAULT_S

    @pytest.mark.parametrize("bad", ["nan", "inf", "-inf"])
    def test_non_finite_falls_back(self, monkeypatch, bad):
        # nan defeats the floor comparison (``nan < floor`` is False)
        # and would ride into ``httpx.Timeout(read=nan)`` — httpx
        # accepts it, downstream behaviour undefined; inf passes the
        # floor and silently disables the watchdog. Both must fall
        # back to the default.
        monkeypatch.setenv(_STALL_ENV, bad)
        assert _stream_stall_s() == _STREAM_STALL_DEFAULT_S

    def test_default_bounds_both_directions(self):
        # Direction 1: healthy inter-event pauses (extended thinking,
        # long tool deliberation) are real — the default must sit
        # comfortably above them.
        assert _STREAM_STALL_DEFAULT_S >= 60.0
        # Direction 2: the watchdog exists to beat the full upstream
        # read timeout to a wedged tunnel; a default approaching that
        # ceiling detects nothing.
        assert _STREAM_STALL_DEFAULT_S <= _UPSTREAM_DEFAULT_TIMEOUT_S / 2
        assert _STREAM_STALL_FLOOR_S >= 1.0


class TestRetryExclusionIsByClass:
    """A stall trip must stay out of the transparent stale-reuse
    retry by CLASS MEMBERSHIP, not merely because the default retry
    ceiling (2s) happens to sit below the stall floor (5s). Those two
    values are independently env-tunable
    (RAPTOR_LLM_DISPATCHER_STALE_RETRY_CEILING_S vs
    RAPTOR_LLM_DISPATCHER_STREAM_STALL_S): a config raising the
    ceiling past the stall window would make a class-eligible
    ReadTimeout re-send reachable — the double-bill the exclusion
    exists to prevent. Pin the tuple itself so widening it fails
    loudly under EVERY configuration, not just the default one."""

    def test_read_timeout_is_not_stale_retry_eligible(self):
        assert httpx.ReadTimeout not in _STALE_REUSE_ERRORS
        assert not issubclass(httpx.ReadTimeout, _STALE_REUSE_ERRORS)

    def test_no_timeout_shape_is_stale_retry_eligible(self):
        # Broader direction of the same property: any timeout means
        # the upstream may already be generating (and billing) — no
        # timeout class may ever enter the retry tuple.
        for exc_type in _STALE_REUSE_ERRORS:
            assert not issubclass(exc_type, httpx.TimeoutException)


class TestStreamDetection:

    def test_streaming_body_detected(self):
        assert _request_wants_stream(_STREAMING_BODY) is True

    @pytest.mark.parametrize("body", [
        b"",
        _PLAIN_BODY,
        json.dumps({"model": "m", "stream": False}).encode(),
        json.dumps({"model": "m", "stream": "true"}).encode(),  # non-bool
        json.dumps([{"stream": True}]).encode(),  # non-dict
        b'{"stream": tru',  # invalid JSON that mentions the key
    ])
    def test_everything_else_is_not_streaming(self, body):
        # Fail-safe direction: only a positively identified streaming
        # request gets the tighter window; ambiguity keeps the full
        # read timeout.
        assert _request_wants_stream(body) is False


_GEMINI_STREAM_PATH = "/v1beta/models/gemini-x:streamGenerateContent?alt=sse"


class TestUrlMethodStreamDetection:
    """Provider surfaces that select streaming by PATH carry no JSON
    ``"stream"`` field — Gemini's ``:streamGenerateContent`` method
    and Bedrock's ``invoke-with-response-stream`` /
    ``converse-stream`` actions. They previously read as
    non-streaming (fail-safe, but the watchdog silently did not
    cover them); the path classifier gives them the same stall
    window. Matching is exact and path-anchored: a false positive
    TIGHTENS a non-streaming request's read timeout — the unsafe
    direction — so nothing looser than the known method names may
    match."""

    @pytest.mark.parametrize("path", [
        _GEMINI_STREAM_PATH,
        "/v1beta/models/gemini-x:streamGenerateContent",
        "/model/some.model-id/invoke-with-response-stream",
        "/model/some.model-id/converse-stream",
        "/model/some.model-id/converse-stream/",  # trailing slash
    ])
    def test_url_method_streaming_paths_detected(self, path):
        assert _request_wants_stream(_PLAIN_BODY, path) is True

    @pytest.mark.parametrize("path", [
        "",
        "/v1/messages",
        "/v1beta/models/gemini-x:generateContent",  # non-stream sibling
        "/model/m/invoke",  # non-stream sibling
        "/model/m/converse",  # non-stream sibling
        "/model/m/xconverse-stream",  # segment-anchored, not substring
        "/v1/messages?x=:streamGenerateContent",  # marker in query only
        "/v1beta/models/g:streamGenerateContent#f",  # fragment: refuse
        # Case-sensitivity pins: the seed bans case folding — a
        # case-variant path is not a known provider method.
        "/v1beta/models/g:streamgeneratecontent",
        "/model/m/Converse-Stream",
        # Fragment AFTER query: endswith alone would match once the
        # query is stripped — only the fragment guard refuses it.
        "/v1beta/models/g:streamGenerateContent?alt=sse#frag",
        # Trailing-slash tolerance stops at one: multi-slash shapes
        # are not paths any provider publishes for these methods.
        "/model/some.model-id/converse-stream//",
        "/model/some.model-id/converse-stream///",
    ])
    def test_everything_else_stays_body_based(self, path):
        assert _request_wants_stream(_PLAIN_BODY, path) is False

    def test_body_detection_still_wins_on_plain_paths(self):
        assert _request_wants_stream(_STREAMING_BODY, "/v1/messages") is True

    def test_url_streaming_request_gets_stall_window(self, monkeypatch):
        monkeypatch.setenv(_STALL_ENV, "45")
        timeout = _upstream_timeout_for(_PLAIN_BODY, _GEMINI_STREAM_PATH)
        assert timeout.read == 45.0


class TestTimeoutSelection:

    def test_streaming_request_gets_stall_window(self, monkeypatch):
        monkeypatch.setenv(_STALL_ENV, "45")
        timeout = _upstream_timeout_for(_STREAMING_BODY)
        assert timeout.read == 45.0
        assert timeout.connect == _UPSTREAM_CONNECT_TIMEOUT_S

    def test_plain_request_keeps_full_timeout(self, monkeypatch):
        monkeypatch.setenv(_STALL_ENV, "45")
        timeout = _upstream_timeout_for(_PLAIN_BODY)
        assert timeout.read == float(_UPSTREAM_DEFAULT_TIMEOUT_S)

    def test_watchdog_only_tightens_never_widens(self, monkeypatch):
        # An operator-set upstream timeout stricter than the stall
        # window must stand — the watchdog is a detector, not a
        # timeout extension.
        monkeypatch.setenv(
            "RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S", "60",
        )
        monkeypatch.setenv(_STALL_ENV, "120")
        timeout = _upstream_timeout_for(_STREAMING_BODY)
        assert timeout.read == 60.0


@pytest.mark.upstream_forward
class TestRelayWiring:
    """The relay passes the per-request window to the shard client."""

    def _recorded_timeout(
        self, fake_creds, tmp_path, body: bytes,
        path: str = "/anthropic/v1/messages",
    ):
        d = LLMDispatcher(
            run_id="stall-wiring", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=100,
        )
        try:
            shards = d._upstream_client_shards()
            client = shards.clients[0]
            seen: dict = {}
            real_stream = client.stream

            def recording_stream(method, url, **kwargs):
                seen["timeout"] = kwargs.get("timeout")
                return real_stream(
                    "GET", "http://127.0.0.1:1/unreachable",
                    timeout=kwargs.get("timeout"),
                )

            client.stream = recording_stream  # type: ignore[method-assign]
            token = _worker_token(d)
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            with httpx.Client(transport=transport, timeout=10.0) as c:
                c.post(
                    f"http://_{path}",
                    headers={_TOKEN_HEADER: token},
                    content=body,
                )
            return seen["timeout"]
        finally:
            d.shutdown()

    def test_streaming_relay_rides_the_stall_window(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv(_STALL_ENV, "33")
        timeout = self._recorded_timeout(fake_creds, tmp_path, _STREAMING_BODY)
        assert timeout is not None
        assert timeout.read == 33.0

    def test_plain_relay_keeps_the_full_window(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv(_STALL_ENV, "33")
        timeout = self._recorded_timeout(fake_creds, tmp_path, _PLAIN_BODY)
        assert timeout is not None
        assert timeout.read == float(_UPSTREAM_DEFAULT_TIMEOUT_S)

    def test_url_method_streaming_relay_rides_the_stall_window(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        # Pins the call-site pass-through: the relay must hand the
        # request PATH to the timeout selector, so a Gemini-shaped
        # streaming URL with a plain body rides the stall window
        # end-to-end.
        monkeypatch.setenv(_STALL_ENV, "33")
        timeout = self._recorded_timeout(
            fake_creds, tmp_path, _PLAIN_BODY,
            path="/anthropic/v1/models/m:streamGenerateContent",
        )
        assert timeout is not None
        assert timeout.read == 33.0

    def _recorded_watcher_stall(
        self, fake_creds, tmp_path, monkeypatch, body: bytes,
    ) -> float | None:
        """Capture the ``stream_stall_s`` the relay hands its watcher
        (same technique as ``_recorded_timeout``: wrap the module
        global, drive one request, read the recorded kwarg). The
        upstream rule points at an unreachable port — the request
        502s, but the watcher is constructed before the connect."""
        seen: dict = {}
        real_watcher = dispatcher_server._OrphanWatcher

        def recording_watcher(
            *args: object, **kwargs: object,
        ) -> _OrphanWatcher:
            seen["stream_stall_s"] = kwargs.get("stream_stall_s")
            return real_watcher(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(
            dispatcher_server, "_OrphanWatcher", recording_watcher,
        )
        d = LLMDispatcher(
            run_id="stall-arm-wiring", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=100,
        )
        original = d._rules["anthropic"]
        d._rules["anthropic"] = ProviderRule(
            name=original.name,
            upstream_base_url="http://127.0.0.1:1",
            inject_headers=original.inject_headers,
            strip_request_headers=original.strip_request_headers,
        )
        try:
            token = _worker_token(d)
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            with httpx.Client(transport=transport, timeout=10.0) as c:
                c.post(
                    "http://_/anthropic/v1/messages",
                    headers={_TOKEN_HEADER: token},
                    content=body,
                )
            return seen["stream_stall_s"]
        finally:
            d.shutdown()

    def test_plain_relay_never_arms_the_stall_watcher(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        # Pins the construction-site conditional: a NON-streaming
        # relay must hand its watcher stream_stall_s=None — its
        # single body read legitimately spans the whole generation,
        # and an armed watcher would tear it down at the stall
        # window. (Removing the conditional — arming every relay
        # unconditionally — survives every other test in the
        # battery: only this wiring pin kills it.)
        monkeypatch.setenv(_STALL_ENV, "77")
        stall = self._recorded_watcher_stall(
            fake_creds, tmp_path, monkeypatch, _PLAIN_BODY,
        )
        assert stall is None

    def test_streaming_relay_arms_the_stall_watcher(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        # The positive direction of the same pin: a streaming
        # relay's watcher carries the stall window.
        monkeypatch.setenv(_STALL_ENV, "77")
        stall = self._recorded_watcher_stall(
            fake_creds, tmp_path, monkeypatch, _STREAMING_BODY,
        )
        assert stall == 77.0


@pytest.mark.upstream_forward
class TestWatchdogTrips:
    # Genuine cost, slow tier: each trip test holds a real wedge for
    # the stall window before the watchdog fires, and the window is
    # already pinned at _STREAM_STALL_FLOOR_S (5s) — any lower value
    # falls back to the default (test_below_floor_falls_back), so the
    # ~6s call cannot shrink without weakening the trip behaviour
    # under test. The wait IS the subject; nothing to mock.
    pytestmark = pytest.mark.slow

    def test_mid_stream_wedge_trips_within_the_window(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """SSE head + one event, then a silent wedge: the relay must
        abort on ReadTimeout in roughly the stall window — nowhere
        near the full upstream timeout — and must NOT transparently
        retry (one upstream connection total: re-sending a
        mid-generation request double-bills)."""
        monkeypatch.setenv(_STALL_ENV, "5")
        upstream = _WedgedUpstream("sse_wedge", wedge_s=30.0)
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            received = b""
            start = time.monotonic()
            with contextlib.suppress(httpx.HTTPError):
                with httpx.Client(transport=transport, timeout=30.0) as c:
                    with c.stream(
                        "POST", "http://_/anthropic/v1/messages",
                        headers={_TOKEN_HEADER: token},
                        content=_STREAMING_BODY,
                    ) as resp:
                        for chunk in resp.iter_raw():
                            received += chunk
            elapsed = time.monotonic() - start
            assert _SSE_CHUNK_ONE in received  # head + first event relayed
            assert elapsed < 15.0  # window ~5s, not the 30s wedge
            errors = _wait_audit(d, "request.error")
            assert errors
            assert errors[0]["reason"] == "ReadTimeout"
            assert errors[0]["response_started"] is True
            # Native per-read trip, not a watcher stall cancel: the
            # provenance flag must say so.
            assert errors[0]["stall_abort"] is False
            assert upstream.connections == 1  # no transparent retry
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_head_wedge_trips_and_is_not_retried(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """A wedge before the response head trips the same window on
        the stream OPEN. Timeouts stay excluded from the stale-reuse
        retry — the request may already be generating upstream."""
        monkeypatch.setenv(_STALL_ENV, "5")
        upstream = _WedgedUpstream("head_wedge", wedge_s=30.0)
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            start = time.monotonic()
            with httpx.Client(transport=transport, timeout=30.0) as c:
                resp = c.post(
                    "http://_/anthropic/v1/messages",
                    headers={_TOKEN_HEADER: token},
                    content=_STREAMING_BODY,
                )
            elapsed = time.monotonic() - start
            assert resp.status_code == 502
            assert elapsed < 15.0
            errors = _wait_audit(d, "request.error")
            assert errors
            assert errors[0]["reason"] == "ReadTimeout"
            assert errors[0]["response_started"] is False
            # The watcher's stall arm never owns the pre-first-event
            # phase (it arms at the first body chunk): a head-dwell
            # trip is always the native per-read timeout.
            assert errors[0]["stall_abort"] is False
            assert upstream.connections == 1  # retry-excluded
            assert not _audit_events(d, "request.retry")
        finally:
            upstream.shutdown()
            d.shutdown()


class _FakeNetStream:
    """Stands in for the httpcore network-stream extension: the only
    surface the watcher touches is ``get_extra_info("socket")``."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def get_extra_info(self, name: str) -> socket.socket | None:
        return self._sock if name == "socket" else None


class _FakeResponse:
    """Duck-typed httpx.Response for the watcher's cancel path: it
    reads ``http_version`` and ``extensions["network_stream"]`` only."""

    def __init__(
        self, sock: socket.socket, http_version: str = "HTTP/1.1",
    ) -> None:
        self.http_version = http_version
        self.extensions = {"network_stream": _FakeNetStream(sock)}


class TestStallArmUnit:
    """The watcher's post-first-chunk stall arm, in isolation.

    The arm exists for the phase the native per-read timeout cannot
    police tightly: after the first upstream body byte, the HTTP/1.1
    body-read timeout is already captured inside httpcore, so the
    only way to enforce a tighter inter-chunk window is the watcher's
    cross-thread socket teardown. These tests pin the arm's contract:
    armed by the first chunk stamp (never earlier), refreshed by every
    stamp, one-shot, lock-excluded against ``stop()``, and flag-only
    on HTTP/2's shared socket.
    """

    @pytest.fixture
    def rig(self):
        """Watcher on live socketpairs; everything torn down at exit."""
        created: dict = {}

        def build(
            stall: float | None,
            poll: float = 0.05,
            http_version: str = "HTTP/1.1",
        ) -> tuple[_OrphanWatcher, socket.socket, socket.socket]:
            worker_a, worker_b = socket.socketpair()
            up_a, up_b = socket.socketpair()
            watcher = _OrphanWatcher(
                worker_a, poll, lambda cancel: None,
                stream_stall_s=stall,
            )
            watcher.attach_response(_FakeResponse(up_a, http_version))
            created["all"] = (watcher, worker_a, worker_b, up_a, up_b)
            return watcher, up_a, up_b

        yield build
        watcher, *socks = created["all"]
        watcher.stop()
        watcher.join()
        for s in socks:
            with contextlib.suppress(OSError):
                s.close()

    @staticmethod
    def _wait_for(event: threading.Event, timeout: float = 3.0) -> bool:
        return event.wait(timeout)

    def test_never_fires_before_first_chunk(self, rig):
        # Direction 1 of the phase split: the pre-first-event dwell
        # belongs to the native request timeout — a watcher that fired
        # before any chunk would re-create the slow-start kill from
        # inside the fix.
        watcher, _up_a, _up_b = rig(stall=0.2)
        time.sleep(0.7)
        assert not watcher.stall_fired.is_set()

    def test_chunk_stamp_resets_deadline(self, rig):
        watcher, _up_a, _up_b = rig(stall=0.3)
        for _ in range(6):
            watcher.note_upstream_chunk()
            time.sleep(0.1)
        # 0.6s elapsed since the FIRST stamp — twice the window — but
        # no inter-stamp gap ever exceeded it.
        assert not watcher.stall_fired.is_set()

    def test_fire_is_oneshot_sets_flag_and_shuts_socket(self, rig):
        watcher, _up_a, up_b = rig(stall=0.2)
        watcher.note_upstream_chunk()
        assert self._wait_for(watcher.stall_fired)
        # HTTP/1.x cancel: the upstream socket is torn down, which is
        # what wakes a relay thread blocked in a read.
        up_b.settimeout(2.0)
        assert up_b.recv(1) == b""
        # One-shot: the watcher thread retires after firing (same
        # contract as the worker-gone arm) and never re-fires.
        watcher._thread.join(timeout=2.0)
        assert not watcher._thread.is_alive()
        # The worker is alive and untouched — a stall is not an orphan.
        assert not watcher.worker_gone.is_set()

    def test_stop_excludes_late_stall_cancel(self, rig):
        # Pool safety, same doctrine as the orphan cancel: once the
        # relay declares the stream drained, a late stall detection
        # must not shut down a socket that may already be back in the
        # shared connection pool.
        watcher, up_a, _up_b = rig(stall=0.2)
        watcher.note_upstream_chunk()
        watcher.stop()
        time.sleep(0.6)
        assert not watcher.stall_fired.is_set()
        up_a.sendall(b"x")  # would raise if the socket had been shut

    def test_h2_response_is_flag_only(self, rig):
        # An HTTP/2 socket is shared with multiplexed sibling relays:
        # shutting it down would abort every one of them. Flag-only —
        # detection falls back to the native per-read bound.
        watcher, up_a, _up_b = rig(stall=0.2, http_version="HTTP/2")
        watcher.note_upstream_chunk()
        assert self._wait_for(watcher.stall_fired)
        up_a.sendall(b"x")  # socket untouched

    def test_none_stall_never_arms(self, rig):
        # Non-streaming relays construct the watcher with
        # stream_stall_s=None: their single body read legitimately
        # spans the whole generation, so chunk stamps must be inert.
        watcher, _up_a, _up_b = rig(stall=None)
        watcher.note_upstream_chunk()
        time.sleep(0.5)
        assert not watcher.stall_fired.is_set()

    def test_under_lock_recheck_spares_resumed_stream(self, rig):
        # The poll loop pre-checks the deadline cheaply, then
        # _fire_stall re-checks under the lock: a chunk landing
        # between the two checks proves the stream resumed within the
        # poll tick and is spared. Simulate the race deterministically
        # by calling the fire path directly with a fresh stamp (poll
        # interval parked high so the loop itself stays dormant).
        watcher, _up_a, up_b = rig(stall=0.2, poll=60.0)
        watcher.note_upstream_chunk()
        assert watcher._fire_stall() is None    # fresh stamp: spared
        assert not watcher.stall_fired.is_set()
        time.sleep(0.4)
        # Stale stamp: fires, reporting the cancel action taken.
        assert watcher._fire_stall() == "upstream_shutdown"
        assert watcher.stall_fired.is_set()
        up_b.settimeout(2.0)
        assert up_b.recv(1) == b""

    def test_flag_only_fire_keeps_orphan_duty_alive(self):
        # An h2 stall fire cannot tear the shared socket down
        # (flag-only) — the relay thread stays blocked in its read
        # until the native timeout, and the worker may abandon it
        # meanwhile. The watcher's PRIMARY duty must therefore keep
        # polling: a worker death after a flag-only fire still sets
        # worker_gone and audits the orphan cancel. (Pre-fix the
        # thread retired on ANY fire, so the abandonment went
        # unnoticed until write time and was never audited.)
        worker_a, worker_b = socket.socketpair()
        up_a, up_b = socket.socketpair()
        cancels: list[str] = []
        gone_audited = threading.Event()

        def on_gone(cancel: str) -> None:
            cancels.append(cancel)
            gone_audited.set()

        watcher = _OrphanWatcher(
            worker_a, 0.05, on_gone, stream_stall_s=0.2,
        )
        watcher.attach_response(_FakeResponse(up_a, "HTTP/2"))
        try:
            watcher.note_upstream_chunk()
            assert watcher.stall_fired.wait(3.0)
            up_a.sendall(b"x")  # flag-only: shared socket untouched
            assert watcher._thread.is_alive()  # duty NOT retired
            # The worker abandons AFTER the flag-only fire:
            worker_b.close()
            assert watcher.worker_gone.wait(3.0)
            assert gone_audited.wait(3.0)
            assert cancels == ["flag_only"]
        finally:
            watcher.stop()
            watcher.join()
            for s in (worker_a, worker_b, up_a, up_b):
                with contextlib.suppress(OSError):
                    s.close()

    def test_flag_only_fire_never_fires_or_cancels_again(self):
        # One-shot survives the fix in the OTHER direction: after a
        # flag-only fire the deadline stays passed forever (no more
        # chunks), but the arm must never fire or cancel again — a
        # re-fire against a later-attached teardown-capable response
        # would kill a socket the first fire deliberately spared.
        worker_a, worker_b = socket.socketpair()
        up_a, up_b = socket.socketpair()
        up2_a, up2_b = socket.socketpair()
        watcher = _OrphanWatcher(
            worker_a, 0.05, lambda cancel: None, stream_stall_s=0.2,
        )
        watcher.attach_response(_FakeResponse(up_a, "HTTP/2"))
        try:
            watcher.note_upstream_chunk()
            assert watcher.stall_fired.wait(3.0)
            # Deadline still passed; a teardown-capable h1 response
            # is now attached. If the arm could re-fire, the poll
            # loop would shut this socket down within a few ticks.
            watcher.attach_response(_FakeResponse(up2_a, "HTTP/1.1"))
            time.sleep(0.5)
            up2_a.sendall(b"x")  # untouched: no second cancel
            assert watcher._fire_stall() is None  # direct probe too
            assert not watcher.worker_gone.is_set()
        finally:
            watcher.stop()
            watcher.join()
            for s in (worker_a, worker_b, up_a, up_b, up2_a, up2_b):
                with contextlib.suppress(OSError):
                    s.close()
