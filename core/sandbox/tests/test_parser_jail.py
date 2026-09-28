"""Confined request-line parser jail (parser_jail / _parser_jail_child /
_request_head) and its proxy seam.

Five properties under test:

- Differential equivalence: the jailed round-trip returns EXACTLY what
  the extracted in-process parser returns — same accept/deny, same
  host/port, same refusal reason strings — over a corpus of normal and
  hostile request lines. The extracted parser IS the former inline
  parse, so this pins old-vs-jailed equivalence.
- Crash isolation: a worker killed between requests respawns
  transparently; a worker dying ON a request costs that request a
  clean denial and nothing else.
- Fail-closed: a jail whose worker cannot be spawned and confined
  raises, and EgressProxy construction refuses to come up on it;
  mid-life unavailability answers 503 (never an inline parse).
- Parent re-validation: a hostile worker (wrong frame id, oversized
  frame, garbage JSON, non-printable host, wrong field types, missing
  or out-of-vocabulary census) is killed and its output never
  consumed — driven through a fake in-process worker so every hostile
  shape is deterministic.
- Method census: the parser classifies every line for the proxy's
  requests_connect / requests_non_connect counters; the differential
  test pins the classification through the jailed round-trip
  (ParseRefusal equality includes the census field), and the live
  proxy counts from the re-validated verdict.
- Degraded floor: a Landlock-less worker produces the startup warning
  and the per-registration `parser_jail_degraded` audit marker; on
  Landlock-capable hosts the real worker reports confinement.

Real-worker tests spawn the actual child process (interpreter +
self-confinement); hostile-worker tests monkeypatch the module's
`subprocess` handle with an in-process fake so no real child is
involved and every protocol deviation is scripted.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
import types
from typing import Callable, Optional

import pytest

from core.sandbox import parser_jail
from core.sandbox import proxy as proxy_mod
from core.sandbox._parser_jail_child import (
    FRAME_HEADER,
    MAX_FRAME_PAYLOAD,
    READY_FRAME_ID,
)
from core.sandbox._request_head import (
    CENSUS_CONNECT,
    CENSUS_NEITHER,
    CENSUS_NON_CONNECT,
    ParsedRequestLine,
    ParseRefusal,
    parse_connect_request_line,
)

# ---------------------------------------------------------------------------
# corpus: normal + hostile request lines (raw bytes, CRLF already
# stripped — exactly what the proxy's line reader hands over)
# ---------------------------------------------------------------------------

_LONG_HOST_ACCEPT = b"a" * (4094 - len(b"CONNECT :443 HTTP/1.1"))
_LONG_HOST_REFUSE = b"a" * (4095 - len(b"CONNECT :443 HTTP/1.1"))

CORPUS: "list[bytes]" = [
    # normal
    b"CONNECT example.com:443 HTTP/1.1",
    b"CONNECT example.com:443 HTTP/1.0",
    b"CONNECT [::1]:443 HTTP/1.1",
    b"CONNECT 10.0.0.1:8443 HTTP/1.1",
    # empty host is ACCEPTED by the parse (policy denies downstream)
    b"CONNECT :443 HTTP/1.1",
    # whitespace quirks str.split() tolerates (contract, not bug-fix)
    b"CONNECT\texample.com:443\tHTTP/1.1",
    b"  CONNECT   example.com:443   HTTP/1.1  ",
    # int() quirks preserved verbatim
    b"CONNECT example.com:4_43 HTTP/1.1",
    b"CONNECT example.com:+443 HTTP/1.1",
    b"CONNECT example.com:00443 HTTP/1.1",
    # bracket edge cases
    b"CONNECT ]example.com[:443 HTTP/1.1",
    b"CONNECT [::1:443 HTTP/1.1",
    b"CONNECT example.com:443:444 HTTP/1.1",
    # malformed
    b"",
    b"GET / HTTP/1.1",
    b"connect example.com:443 HTTP/1.1",
    b"CONNECT example.com:443",
    b"CONNECT example.com:443 HTTPX/1.1",
    b"CONNECT example.com:443 HTTP/1.1 extra",
    b"CONNECT example.com: 443 HTTP/1.1",
    # missing / bad ports
    b"CONNECT example.com HTTP/1.1",
    b"CONNECT example.com:notaport HTTP/1.1",
    b"CONNECT example.com:99999 HTTP/1.1",
    b"CONNECT example.com:0 HTTP/1.1",
    b"CONNECT example.com:-1 HTTP/1.1",
    # non-printable / injection attempts
    b"CONNECT evil\x1b[31m.com:443 HTTP/1.1",
    b"CONNECT exa\x00mple.com:443 HTTP/1.1",
    b"CONNECT example.com:443\x07 HTTP/1.1",
    b"CONNECT a\rb:443 HTTP/1.1",
    b"CONNECT a\nb:443 HTTP/1.1",
    # latin-1 high bytes: \x85 (NEL) is unicode whitespace post-decode,
    # \xa0 (NBSP) likewise — decode-then-split order is contract
    "CONNECT h\x85ost:443 HTTP/1.1".encode("latin-1"),
    "CONNECT h\xa0ost:443 HTTP/1.1".encode("latin-1"),
    "CONNECT h\xf6st:443 HTTP/1.1".encode("latin-1"),
    # length boundary: 4094 bytes accepted (cap counts the CRLF),
    # 4095 refused
    b"CONNECT " + _LONG_HOST_ACCEPT + b":443 HTTP/1.1",
    b"CONNECT " + _LONG_HOST_REFUSE + b":443 HTTP/1.1",
    b"CONNECT " + b"a" * 6000 + b":443 HTTP/1.1",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_jail():
    """A dedicated real-worker jail, torn down after the test."""
    jail = parser_jail.ParserJail()
    jail.start()
    yield jail
    jail.stop()


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


def _read_status(sock: socket.socket, timeout: float) -> "int | None":
    """First response status code, or None if the peer closed/stalled
    without sending one."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
    except OSError:
        return None
    parts = buf.split(b"\r\n", 1)[0].split(None, 2)
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


def _send_frame(sock: socket.socket, req_id: int, payload: bytes,
                declared_len: "int | None" = None) -> None:
    length = len(payload) if declared_len is None else declared_len
    sock.sendall(FRAME_HEADER.pack(length, req_id) + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("fake worker: peer closed")
        buf += chunk
    return buf


# A responder receives (req_id, payload) and either handles the reply
# itself via the socket or returns False to close the socket (crash).
_Responder = Callable[[socket.socket, int, bytes], bool]


def _verdict_bytes(payload: bytes) -> bytes:
    """The honest JSON verdict for *payload*, as the child would send it."""
    result = parse_connect_request_line(payload)
    if isinstance(result, ParsedRequestLine):
        verdict: dict = {"ok": True, "host": result.host,
                         "port": result.port}
    else:
        verdict = {"ok": False, "reason": result.reason,
                   "host": result.host, "port": result.port,
                   "census": result.census}
    return json.dumps(verdict).encode("utf-8")


def _honest_responder(sock: socket.socket, req_id: int,
                      payload: bytes) -> bool:
    _send_frame(sock, req_id, _verdict_bytes(payload))
    return True


class _FakeWorker:
    """In-process stand-in for the child: drives the wire protocol from
    a thread so hostile shapes are deterministic. Duck-types the
    subprocess.Popen surface the manager touches (poll/kill/wait/pid).
    """

    def __init__(self, argv: list, *, pass_fds: tuple,
                 ready: "dict | None", responder: _Responder,
                 **_kwargs: object) -> None:
        # The manager closes its child_sock handle right after Popen
        # returns — keep our own duplicate of the fd.
        self._sock = socket.socket(fileno=os.dup(pass_fds[0]))
        self._ready = ready
        self._responder = responder
        self._dead = threading.Event()
        self.pid = -1  # never signalled: kill() is socket teardown here
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            if self._ready is not None:
                _send_frame(self._sock, READY_FRAME_ID,
                            json.dumps(self._ready).encode("utf-8"))
            while True:
                header = _recv_exact(self._sock, FRAME_HEADER.size)
                length, req_id = FRAME_HEADER.unpack(header)
                payload = _recv_exact(self._sock, length)
                if not self._responder(self._sock, req_id, payload):
                    break
        except OSError:
            pass
        finally:
            self.kill()

    def poll(self) -> "int | None":
        return 0 if self._dead.is_set() else None

    def kill(self) -> None:
        self._dead.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def wait(self, timeout: "float | None" = None) -> int:
        self._thread.join(timeout)
        return 0


def _fake_subprocess(ready: "dict | None",
                     responder: _Responder) -> types.SimpleNamespace:
    """A subprocess-module stand-in whose Popen yields a _FakeWorker."""
    def popen(argv: list, **kwargs: object) -> _FakeWorker:
        pass_fds = kwargs.pop("pass_fds")
        return _FakeWorker(argv, pass_fds=pass_fds, ready=ready,
                           responder=responder, **kwargs)
    return types.SimpleNamespace(
        Popen=popen,
        DEVNULL=subprocess.DEVNULL,
        TimeoutExpired=subprocess.TimeoutExpired,
    )


_READY_OK = {"ready": True, "landlock": True, "pid": -1}
_REF = b"CONNECT example.com:443 HTTP/1.1"


# ---------------------------------------------------------------------------
# differential equivalence (real worker)
# ---------------------------------------------------------------------------


class TestDifferentialEquivalence:

    def test_jailed_verdicts_match_inline_parser_over_corpus(
        self, fresh_jail,
    ):
        """For every corpus line the jailed round-trip must return the
        exact struct the in-process parser returns — accept/deny,
        host, port, and refusal reason all identical."""
        for raw in CORPUS:
            expected = parse_connect_request_line(raw)
            got = fresh_jail.parse(raw)
            assert got == expected, (
                f"jailed verdict diverged for {raw[:60]!r}: "
                f"{got!r} != {expected!r}"
            )

    def test_oversized_input_refused_without_worker_involvement(
        self, fresh_jail,
    ):
        raw = b"CONNECT " + b"x" * MAX_FRAME_PAYLOAD + b":443 HTTP/1.1"
        got = fresh_jail.parse(raw)
        assert got == ParseRefusal(reason="empty/overlong CONNECT line")
        # worker still healthy afterwards
        assert fresh_jail.parse(_REF) == ParsedRequestLine(
            host="example.com", port=443)


# ---------------------------------------------------------------------------
# method census classification (pure parser — the source of truth the
# proxy's requests_connect / requests_non_connect counters consume)
# ---------------------------------------------------------------------------


class TestCensusClassification:

    @pytest.mark.parametrize("raw,census", [
        # structurally well-formed CONNECT, target refused later →
        # still "connect" (counted BEFORE target validation, exactly
        # where the former inline count sat)
        (b"CONNECT evil\x1b[31m.com:443 HTTP/1.1", CENSUS_CONNECT),
        (b"CONNECT example.com HTTP/1.1", CENSUS_CONNECT),
        (b"CONNECT example.com:notaport HTTP/1.1", CENSUS_CONNECT),
        (b"CONNECT example.com:99999 HTTP/1.1", CENSUS_CONNECT),
        (b"CONNECT example.com:0 HTTP/1.1", CENSUS_CONNECT),
        # non-CONNECT method → "non_connect"
        (b"GET / HTTP/1.1", CENSUS_NON_CONNECT),
        (b"connect example.com:443 HTTP/1.1", CENSUS_NON_CONNECT),
        # malformed with method CONNECT, or nothing at all → "neither"
        (b"CONNECT example.com:443", CENSUS_NEITHER),
        (b"CONNECT example.com:443 HTTPX/1.1", CENSUS_NEITHER),
        (b"CONNECT example.com:443 HTTP/1.1 extra", CENSUS_NEITHER),
        (b"", CENSUS_NEITHER),
        (b"   ", CENSUS_NEITHER),
        # overlong lines are refused before any split → "neither"
        (b"CONNECT " + b"a" * 6000 + b":443 HTTP/1.1", CENSUS_NEITHER),
    ])
    def test_refusals_classify_for_the_method_census(self, raw, census):
        result = parse_connect_request_line(raw)
        assert isinstance(result, ParseRefusal)
        assert result.census == census

    def test_synthetic_refusal_defaults_to_neither(self):
        """Refusals built OUTSIDE the parse (worker crash, protocol
        violation) must never inflate either counter."""
        assert ParseRefusal(reason="synthetic").census == CENSUS_NEITHER


# ---------------------------------------------------------------------------
# crash isolation + respawn (real worker for between-requests; fake
# worker for deterministic mid-request death)
# ---------------------------------------------------------------------------


class TestCrashIsolation:

    def test_worker_killed_between_requests_respawns_transparently(
        self, fresh_jail,
    ):
        assert fresh_jail.parse(_REF) == ParsedRequestLine(
            host="example.com", port=443)
        proc = fresh_jail._proc
        assert proc is not None
        first_pid = proc.pid
        proc.kill()
        proc.wait()
        # Next parse detects the dead worker and respawns before the
        # round-trip — no denial for a kill that raced no request.
        assert fresh_jail.parse(_REF) == ParsedRequestLine(
            host="example.com", port=443)
        assert fresh_jail._proc is not None
        assert fresh_jail._proc.pid != first_pid

    def test_worker_death_mid_request_denies_cleanly_and_respawns(
        self, monkeypatch,
    ):
        calls = {"n": 0}

        def dies_on_first_request(sock: socket.socket, req_id: int,
                                  payload: bytes) -> bool:
            calls["n"] += 1
            if calls["n"] == 1:
                return False  # close the socket instead of replying
            return _honest_responder(sock, req_id, payload)

        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(_READY_OK, dies_on_first_request))
        jail = parser_jail.ParserJail()
        jail.start()
        try:
            denied = jail.parse(_REF)
            assert denied == ParseRefusal(
                reason="request-line parser crashed on this input "
                       "(worker respawned)")
            # the poison request cost exactly itself: next one is served
            assert jail.parse(_REF) == ParsedRequestLine(
                host="example.com", port=443)
        finally:
            jail.stop()


# ---------------------------------------------------------------------------
# fail-closed
# ---------------------------------------------------------------------------


class TestFailClosed:

    def test_spawn_failure_raises_and_backs_off(self, monkeypatch):
        popen_calls = {"n": 0}

        def broken_popen(argv: list, **kwargs: object) -> _FakeWorker:
            popen_calls["n"] += 1
            raise OSError("no such interpreter")

        monkeypatch.setattr(
            parser_jail, "subprocess",
            types.SimpleNamespace(
                Popen=broken_popen,
                DEVNULL=subprocess.DEVNULL,
                TimeoutExpired=subprocess.TimeoutExpired,
            ))
        jail = parser_jail.ParserJail()
        with pytest.raises(parser_jail.ParserJailUnavailable):
            jail.start()
        assert popen_calls["n"] == 1
        # Immediate retry is inside the backoff window: refused WITHOUT
        # another spawn attempt.
        with pytest.raises(parser_jail.ParserJailUnavailable,
                           match="backing off"):
            jail.parse(_REF)
        assert popen_calls["n"] == 1
        # Backoff elapsed + spawn healthy again: recovers, and the
        # failure counter resets on the successful handshake.
        jail._next_spawn_attempt = 0.0
        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(_READY_OK, _honest_responder))
        assert jail.parse(_REF) == ParsedRequestLine(
            host="example.com", port=443)
        assert jail._spawn_failures == 0
        jail.stop()

    def test_confinement_refusal_fails_the_spawn(self, monkeypatch):
        """A child that cannot install Landlock on a capable kernel
        reports ready=false and the spawn fails — never a
        half-confined worker."""
        ready = {"ready": False, "landlock": True, "pid": -1,
                 "error": "landlock install failed: boom"}
        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(ready, _honest_responder))
        jail = parser_jail.ParserJail()
        with pytest.raises(parser_jail.ParserJailUnavailable,
                           match="landlock install failed"):
            jail.start()
        jail.stop()

    def test_stopped_jail_refuses(self, monkeypatch):
        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(_READY_OK, _honest_responder))
        jail = parser_jail.ParserJail()
        jail.start()
        jail.stop()
        with pytest.raises(parser_jail.ParserJailUnavailable,
                           match="stopped"):
            jail.parse(_REF)

    def test_proxy_construction_raises_when_jail_cannot_start(
        self, reset_proxy, monkeypatch,
    ):
        """EgressProxy refuses to come up without a confined parser —
        there is no inline-parse fallback to fall back to."""
        def no_jail() -> parser_jail.ParserJail:
            raise parser_jail.ParserJailUnavailable(
                "parser worker spawn failed: forced by test")

        monkeypatch.setattr(proxy_mod.parser_jail,
                            "get_parser_jail", no_jail)
        with pytest.raises(parser_jail.ParserJailUnavailable):
            proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})

    def test_unavailable_jail_answers_503_with_audit_event(
        self, reset_proxy, monkeypatch,
    ):
        """Mid-life unavailability: 503 + parser_unavailable event —
        the request is refused, never parsed inline."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            class _Unavailable:
                landlocked = True

                @staticmethod
                def parse(raw: bytes) -> None:
                    raise parser_jail.ParserJailUnavailable(
                        "parser worker spawn backing off after "
                        "3 consecutive failure(s)")

            monkeypatch.setattr(proxy, "_parser_jail", _Unavailable())
            token = proxy.register_sandbox()
            s = socket.create_connection(
                ("127.0.0.1", proxy.port), timeout=5)
            try:
                s.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n")
                assert _read_status(s, timeout=5) == 503
            finally:
                s.close()
            deadline = time.monotonic() + 5
            events: "list[dict]" = []
            while time.monotonic() < deadline:
                with proxy._buffer_lock:
                    events = list(proxy._sandbox_buffers.get(token, []))
                if events:
                    break
                time.sleep(0.05)
            results = [e["result"] for e in events]
            assert "parser_unavailable" in results
            proxy.unregister_sandbox(token)
        finally:
            proxy.stop()


# ---------------------------------------------------------------------------
# parent re-validation of hostile worker output
# ---------------------------------------------------------------------------


def _scripted(verdict_bytes: bytes, *, wrong_id: bool = False,
              declared_len: "int | None" = None) -> _Responder:
    def responder(sock: socket.socket, req_id: int,
                  payload: bytes) -> bool:
        resp_id = (req_id + 1) & 0xFFFFFFFF if wrong_id else req_id
        _send_frame(sock, resp_id, verdict_bytes,
                    declared_len=declared_len)
        return True
    return responder


_PROTOCOL_REFUSAL = ParseRefusal(
    reason="request-line parser protocol violation (worker respawned)")


class TestParentRevalidation:

    @pytest.mark.parametrize("case,responder", [
        ("wrong frame id",
         _scripted(json.dumps({"ok": True, "host": "example.com",
                               "port": 443}).encode(), wrong_id=True)),
        ("oversized declared frame",
         _scripted(b"", declared_len=MAX_FRAME_PAYLOAD + 1)),
        ("garbage json",
         _scripted(b"\xff\xfenot json")),
        ("non-object json",
         _scripted(b"[1, 2, 3]")),
        ("ok field not bool",
         _scripted(json.dumps({"ok": "yes", "host": "h",
                               "port": 443}).encode())),
        ("non-printable host",
         _scripted(json.dumps({"ok": True,
                               "host": "evil\x1b[2Jhost",
                               "port": 443}).encode())),
        ("host wrong type",
         _scripted(json.dumps({"ok": True, "host": 7,
                               "port": 443}).encode())),
        ("host overlong",
         _scripted(json.dumps({"ok": True, "host": "a" * 4097,
                               "port": 443}).encode())),
        ("accepted port out of range",
         _scripted(json.dumps({"ok": True, "host": "h",
                               "port": 99999}).encode())),
        ("accepted port bool",
         _scripted(json.dumps({"ok": True, "host": "h",
                               "port": True}).encode())),
        ("accepted port wrong type",
         _scripted(json.dumps({"ok": True, "host": "h",
                               "port": "443"}).encode())),
        ("refusal reason missing",
         _scripted(json.dumps({"ok": False, "host": None,
                               "port": None}).encode())),
        ("refusal reason overlong",
         _scripted(json.dumps({"ok": False, "reason": "r" * 513,
                               "host": None,
                               "port": None}).encode())),
        ("refusal port wrong type",
         _scripted(json.dumps({"ok": False, "reason": "x",
                               "host": None, "port": "443",
                               "census": "connect"}).encode())),
        # An honest refusal port is int()-parsed from the ≤4096-byte
        # request line; this one could not have come from any line.
        ("refusal port beyond line-derived bound",
         _scripted(json.dumps({"ok": False,
                               "reason": "port out of range",
                               "host": "h", "census": "connect",
                               "port": int("9" * 4200)}).encode())),
        # The census drives the proxy's method counters: a worker that
        # stops classifying, or stamps a value outside CENSUS_VALUES,
        # is deviating — kill, never count.
        ("refusal census missing",
         _scripted(json.dumps({"ok": False, "reason": "x",
                               "host": None,
                               "port": None}).encode())),
        ("refusal census out of vocabulary",
         _scripted(json.dumps({"ok": False, "reason": "x",
                               "host": None, "port": None,
                               "census": "connectish"}).encode())),
        ("refusal census wrong type",
         _scripted(json.dumps({"ok": False, "reason": "x",
                               "host": None, "port": None,
                               "census": 1}).encode())),
    ])
    def test_hostile_verdict_never_consumed(self, monkeypatch, case,
                                            responder):
        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(_READY_OK, responder))
        jail = parser_jail.ParserJail()
        jail.start()
        try:
            hostile_worker = jail._proc
            got = jail.parse(_REF)
            assert got == _PROTOCOL_REFUSAL, case
            # the deviating worker was killed, never re-consulted
            assert hostile_worker is not None
            assert hostile_worker.poll() is not None, case
            assert jail._proc is None, case
        finally:
            jail.stop()

    def test_hostile_refusal_reason_sanitised(self, monkeypatch):
        """A structurally-valid refusal with terminal escapes in the
        reason passes re-validation with the escapes neutralised —
        never raw into the audit event."""
        verdict = json.dumps({
            "ok": False, "reason": "bad\x1b[2Jline", "host": None,
            "port": None, "census": "neither",
        }).encode()
        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(_READY_OK, _scripted(verdict)))
        jail = parser_jail.ParserJail()
        jail.start()
        try:
            got = jail.parse(_REF)
            assert isinstance(got, ParseRefusal)
            assert "\x1b" not in got.reason
            assert "bad" in got.reason and "line" in got.reason
        finally:
            jail.stop()


# ---------------------------------------------------------------------------
# queued-frame desync: unpredictable ids + pre-send silence check
# ---------------------------------------------------------------------------


class TestQueuedFrameDesync:

    def test_request_ids_are_not_sequential(self, monkeypatch):
        """Request ids must be unpredictable: a guessable (counter)
        sequence would let a hostile worker pre-stamp a frame with the
        next request's id."""
        seen: "list[int]" = []

        def recording(sock: socket.socket, req_id: int,
                      payload: bytes) -> bool:
            seen.append(req_id)
            return _honest_responder(sock, req_id, payload)

        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(_READY_OK, recording))
        jail = parser_jail.ParserJail()
        jail.start()
        try:
            for _ in range(6):
                assert jail.parse(_REF) == ParsedRequestLine(
                    host="example.com", port=443)
        finally:
            jail.stop()
        assert len(seen) == 6
        assert seen != list(range(seen[0], seen[0] + 6))

    def test_prequeued_frame_with_guessed_next_id_refused(
        self, monkeypatch,
    ):
        """A worker that answers request N honestly and pre-queues a
        forged verdict stamped with a guessed next id must never have
        the forgery served as a later request's verdict."""
        forged = json.dumps({"ok": True, "host": "attacker.test",
                             "port": 443}).encode()

        def prequeues(sock: socket.socket, req_id: int,
                      payload: bytes) -> bool:
            honest = _verdict_bytes(payload)
            # One send: the honest reply AND the forged next-id frame
            # are both buffered before the parent can round-trip again.
            sock.sendall(
                FRAME_HEADER.pack(len(honest), req_id) + honest
                + FRAME_HEADER.pack(len(forged),
                                    (req_id + 1) & 0xFFFFFFFF)
                + forged)
            return True

        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(_READY_OK, prequeues))
        jail = parser_jail.ParserJail()
        jail.start()
        try:
            hostile_worker = jail._proc
            assert jail.parse(_REF) == ParsedRequestLine(
                host="example.com", port=443)
            got = jail.parse(_REF)
            assert got == _PROTOCOL_REFUSAL
            assert hostile_worker is not None
            assert hostile_worker.poll() is not None
            assert jail._proc is None
        finally:
            jail.stop()

    def test_unsolicited_pending_bytes_refused_before_send(
        self, monkeypatch,
    ):
        """Unsolicited buffered bytes are detected BEFORE the next
        request is sent: kill + refusal, and the raw request line never
        reaches the deviating worker."""
        second_request_reached_worker = threading.Event()
        calls = {"n": 0}

        def pushes_garbage(sock: socket.socket, req_id: int,
                           payload: bytes) -> bool:
            calls["n"] += 1
            if calls["n"] > 1:
                second_request_reached_worker.set()
                return False
            honest = _verdict_bytes(payload)
            # Honest reply plus trailing unsolicited stream garbage,
            # buffered in one send.
            sock.sendall(FRAME_HEADER.pack(len(honest), req_id)
                         + honest + b"\x00" * 12)
            return True

        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(_READY_OK, pushes_garbage))
        jail = parser_jail.ParserJail()
        jail.start()
        try:
            hostile_worker = jail._proc
            assert jail.parse(_REF) == ParsedRequestLine(
                host="example.com", port=443)
            got = jail.parse(_REF)
            assert got == _PROTOCOL_REFUSAL
            assert hostile_worker is not None
            assert hostile_worker.poll() is not None
            assert jail._proc is None
            assert not second_request_reached_worker.wait(0.5)
        finally:
            jail.stop()


# ---------------------------------------------------------------------------
# child import pinning (real worker): a planted core/ tree under the
# inherited cwd must never import in the child
# ---------------------------------------------------------------------------


# Fully self-contained stand-in: if the child resolved its module from
# the cwd instead of the pinned import root, this speaks just enough of
# the wire protocol to hand every request a sentinel verdict.
_PLANTED_CHILD_SRC = '''\
import json
import socket
import struct
import sys

FRAME_HEADER = struct.Struct(">II")


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def main():
    sock = socket.socket(fileno=int(sys.argv[1]))
    ready = json.dumps(
        {"ready": True, "landlock": True, "pid": 0}).encode()
    sock.sendall(FRAME_HEADER.pack(len(ready), 0) + ready)
    while True:
        header = _recv_exact(sock, FRAME_HEADER.size)
        if header is None:
            return 0
        length, req_id = FRAME_HEADER.unpack(header)
        if _recv_exact(sock, length) is None:
            return 0
        verdict = json.dumps(
            {"ok": True, "host": "planted.invalid", "port": 443},
        ).encode()
        sock.sendall(FRAME_HEADER.pack(len(verdict), req_id) + verdict)


if __name__ == "__main__":
    sys.exit(main())
'''


class TestChildImportPinning:

    def test_planted_core_tree_in_cwd_never_imports(
        self, tmp_path, monkeypatch,
    ):
        """Spawn the manager from a cwd containing a poisoned
        core/sandbox/_parser_jail_child.py: the REAL module must run
        (cwd pinned to the import root + -P strips the cwd sys.path
        entry), so parses come back real, never the sentinel."""
        pkg = tmp_path / "core" / "sandbox"
        pkg.mkdir(parents=True)
        (tmp_path / "core" / "__init__.py").write_text("")
        (pkg / "__init__.py").write_text("")
        (pkg / "_parser_jail_child.py").write_text(_PLANTED_CHILD_SRC)
        monkeypatch.chdir(tmp_path)
        jail = parser_jail.ParserJail()
        jail.start()
        try:
            got = jail.parse(_REF)
            assert got != ParsedRequestLine(host="planted.invalid",
                                            port=443)
            assert got == ParsedRequestLine(host="example.com",
                                            port=443)
        finally:
            jail.stop()


# ---------------------------------------------------------------------------
# concurrency (real worker: mutex-serialised round-trips)
# ---------------------------------------------------------------------------


class TestConcurrency:

    def test_parallel_parses_no_cross_talk(self, fresh_jail):
        """Many threads, distinct targets: every caller gets ITS
        verdict (the mutex + id echo forbid cross-talk)."""
        n_threads, n_iter = 8, 25
        errors: "list[str]" = []

        def worker(idx: int) -> None:
            for i in range(n_iter):
                port = 1 + (idx * n_iter + i) % 65535
                raw = f"CONNECT host-{idx}.test:{port} HTTP/1.1".encode()
                got = fresh_jail.parse(raw)
                want = ParsedRequestLine(host=f"host-{idx}.test",
                                         port=port)
                if got != want:
                    errors.append(f"{got!r} != {want!r}")

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert not errors, errors[:5]


# ---------------------------------------------------------------------------
# degraded floor
# ---------------------------------------------------------------------------


class TestDegradedFloor:

    def test_landlockless_ready_frame_warns_once(self, monkeypatch,
                                                 caplog):
        ready = {"ready": True, "landlock": False, "pid": -1}
        monkeypatch.setattr(
            parser_jail, "subprocess",
            _fake_subprocess(ready, _honest_responder))
        jail = parser_jail.ParserJail()
        with caplog.at_level("WARNING", logger="core.sandbox.parser_jail"):
            jail.start()
        try:
            assert jail.landlocked is False
            degraded = [r for r in caplog.records
                        if "WITHOUT Landlock" in r.getMessage()]
            assert len(degraded) == 1
            # still parses correctly on the degraded floor
            assert jail.parse(_REF) == ParsedRequestLine(
                host="example.com", port=443)
        finally:
            jail.stop()

    def test_degraded_marker_in_every_registration(self, reset_proxy,
                                                   monkeypatch):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            monkeypatch.setattr(proxy._parser_jail, "_landlocked", False)
            token_a = proxy.register_sandbox()
            token_b = proxy.register_sandbox(caller_label="second")
            for token in (token_a, token_b):
                events = proxy.unregister_sandbox(token)
                markers = [e for e in events
                           if e["result"] == "parser_jail_degraded"]
                assert len(markers) == 1
                assert "without Landlock" in markers[0]["reason"]
        finally:
            proxy.stop()

    def test_no_marker_when_landlocked(self, reset_proxy, monkeypatch):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            monkeypatch.setattr(proxy._parser_jail, "_landlocked", True)
            token = proxy.register_sandbox()
            events = proxy.unregister_sandbox(token)
            assert not [e for e in events
                        if e["result"] == "parser_jail_degraded"]
        finally:
            proxy.stop()

    def test_real_worker_confines_on_capable_kernels(self, fresh_jail):
        from core.sandbox.landlock import check_landlock_available
        if not check_landlock_available():
            pytest.skip("kernel lacks Landlock — degraded floor "
                        "covered hermetically above")
        assert fresh_jail.landlocked is True


# ---------------------------------------------------------------------------
# singleton lifecycle
# ---------------------------------------------------------------------------


class TestSingleton:

    def test_get_returns_same_jail_and_reset_tears_down(self):
        parser_jail._reset_for_tests()
        try:
            jail = parser_jail.get_parser_jail()
            assert parser_jail.get_parser_jail() is jail
            assert jail.parse(_REF) == ParsedRequestLine(
                host="example.com", port=443)
            proc = jail._proc
            assert proc is not None and proc.poll() is None
        finally:
            parser_jail._reset_for_tests()
        assert proc.poll() is not None  # worker reaped
        with pytest.raises(parser_jail.ParserJailUnavailable):
            jail.parse(_REF)  # stopped jail stays stopped


# ---------------------------------------------------------------------------
# end-to-end through a live proxy (real worker via the singleton)
# ---------------------------------------------------------------------------


class TestEndToEnd:

    @pytest.mark.parametrize("request_head,expect_status", [
        # malformed line → 400 (parsed in the jail, same as ever)
        (b"GET / HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT example.com HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT example.com:notaport HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT example.com:99999 HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT evil\x1b[31m.com:443 HTTP/1.1\r\n\r\n", 400),
        # well-formed but non-allowlisted → the parse succeeded in the
        # jail and policy (in-process, unchanged) denied it
        (b"CONNECT not-allowed.test:443 HTTP/1.1\r\n\r\n", 403),
    ])
    def test_connect_verdicts_unchanged_through_live_proxy(
        self, reset_proxy, request_head, expect_status,
    ):
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            s = socket.create_connection(
                ("127.0.0.1", proxy.port), timeout=5)
            try:
                s.sendall(request_head)
                assert _read_status(s, timeout=10) == expect_status
            finally:
                s.close()
        finally:
            proxy.stop()

    def test_refusal_attribution_lands_on_the_audit_event(
        self, reset_proxy,
    ):
        """'port out of range' events carry host + the out-of-range
        port, exactly as the inline parse stamped them."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            token = proxy.register_sandbox()
            s = socket.create_connection(
                ("127.0.0.1", proxy.port), timeout=5)
            try:
                s.sendall(b"CONNECT example.com:99999 HTTP/1.1\r\n\r\n")
                assert _read_status(s, timeout=10) == 400
            finally:
                s.close()
            deadline = time.monotonic() + 5
            match: "Optional[dict]" = None
            while time.monotonic() < deadline and match is None:
                with proxy._buffer_lock:
                    for e in proxy._sandbox_buffers.get(token, []):
                        if e.get("reason") == "port out of range":
                            match = dict(e)
                time.sleep(0.05)
            assert match is not None
            assert match["result"] == "bad_request"
            assert match["host"] == "example.com"
            assert match["port"] == 99999
            proxy.unregister_sandbox(token)
        finally:
            proxy.stop()

    def test_method_census_counted_from_jailed_verdicts(
        self, reset_proxy,
    ):
        """The requests_connect / requests_non_connect counters move on
        the same conditions as ever, now fed by the jailed verdict's
        census: well-formed CONNECT counts requests_connect whether or
        not the target validates, a non-CONNECT method counts
        requests_non_connect, and malformed-with-CONNECT counts
        neither."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            for request_head, expect_status in [
                # denied by policy AFTER a successful jailed parse
                (b"CONNECT not-allowed.test:443 HTTP/1.1\r\n\r\n", 403),
                # well-formed CONNECT, target refused in the parse
                (b"CONNECT example.com:99999 HTTP/1.1\r\n\r\n", 400),
                # non-CONNECT method
                (b"GET / HTTP/1.1\r\n\r\n", 400),
                # malformed with method CONNECT: neither counter
                (b"CONNECT example.com:443\r\n\r\n", 400),
            ]:
                s = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=5)
                try:
                    s.sendall(request_head)
                    assert _read_status(s, timeout=10) == expect_status
                finally:
                    s.close()
            deadline = time.monotonic() + 5
            counters: dict = {}
            while time.monotonic() < deadline:
                counters = proxy.snapshot()["counters"]
                if (counters["requests_connect"]
                        + counters["requests_non_connect"]) >= 3:
                    break
                time.sleep(0.05)
            assert counters["requests_connect"] == 2
            assert counters["requests_non_connect"] == 1
        finally:
            proxy.stop()
