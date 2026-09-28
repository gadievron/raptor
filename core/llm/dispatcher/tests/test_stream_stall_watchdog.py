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

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import (
    _STALE_REUSE_ERRORS,
    _STREAM_STALL_DEFAULT_S,
    _STREAM_STALL_FLOOR_S,
    _TOKEN_HEADER,
    _UPSTREAM_CONNECT_TIMEOUT_S,
    _UPSTREAM_DEFAULT_TIMEOUT_S,
    LLMDispatcher,
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
            assert upstream.connections == 1  # retry-excluded
            assert not _audit_events(d, "request.retry")
        finally:
            upstream.shutdown()
            d.shutdown()
