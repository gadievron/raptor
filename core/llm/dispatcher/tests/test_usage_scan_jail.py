"""Confined usage-scan jail (usage_scan_jail / _usage_scan_child /
_usage_scan) — worker lifecycle, re-validation, and the tier ladder.

Properties under test:

- Differential equivalence: the jailed round-trip returns EXACTLY what
  the pure ``scan_usage`` core returns — same model, same counts —
  over a corpus of normal and hostile response windows. The extracted
  core IS the former inline scan, so this pins old-vs-jailed
  equivalence.
- Crash isolation: a worker killed between scans respawns
  transparently; a worker dying ON a scan costs that scan a
  ``scan_failed`` verdict and nothing else — the poison bytes are
  never re-parsed in-process.
- Parent re-validation: a hostile worker (wrong frame id, oversized
  frame, garbage JSON, wrong field types) is killed and its output
  never consumed; values an honest worker could relay from a hostile
  upstream (overlong model, astronomical counts) are
  sanitised/clamped, never kill-worthy.
- Tier ladder: Landlock-less kernels get the jail minus Landlock with
  ONE warning; hosts where the worker cannot run at all step down to
  in-process scanning with ONE warning (sticky after the failure
  threshold); Landlock-CAPABLE kernels whose worker cannot confine
  fail closed — ``ensure_available`` raises and no in-process parse
  ever happens.
- Recycle: the worker is proactively respawned between round-trips
  after the recycle threshold, with no failed verdicts.

Real-worker tests spawn the actual child process (interpreter +
self-confinement); hostile-worker and ladder tests monkeypatch the
module's ``subprocess`` handle with an in-process fake so no real
child is involved and every deviation is scripted (per-tier tests
therefore run hermetically on runners lacking the capability).
"""

from __future__ import annotations

import json
import os
import resource
import socket
import subprocess
import sys
import threading
import types
from typing import Callable

import pytest

from core.llm.dispatcher import usage_scan_jail
from core.llm.dispatcher._usage_scan import scan_usage
from core.llm.dispatcher._usage_scan_child import (
    FRAME_HEADER,
    MAX_FRAME_PAYLOAD,
    READY_FRAME_ID,
    REQ_META,
)
from core.security.log_sanitisation import sanitise_for_terminal

# ---------------------------------------------------------------------------
# corpus: (head, tail, truncated, content_type) — normal + hostile
# response windows, exactly what the relay's scanner buffers hand over
# ---------------------------------------------------------------------------

_SSE_BODY = (
    b'event: message_start\n'
    b'data: {"type":"message_start","message":{"model":"m-1",'
    b'"usage":{"input_tokens":11,"output_tokens":1}}}\n\n'
    b'data: {"type":"message_delta","usage":{"output_tokens":42}}\n\n'
)
_JSON_BODY = (
    b'{"id":"x","model":"m-2","usage":{"input_tokens":7,'
    b'"output_tokens":9,"cache_read_input_tokens":3}}'
)

CORPUS: "list[tuple[bytes, bytes, bool, str | None]]" = [
    # normal SSE (header-classified) and JSON
    (_SSE_BODY, b"", False, "text/event-stream"),
    (_SSE_BODY, b"", False, None),  # body-structure classification
    (_JSON_BODY, b"", False, "application/json"),
    (_JSON_BODY, b"", False, None),
    # truncated JSON: usage recovered from the tail window
    (b'{"id":"y","model":"m-3","content":"',
     b'...","usage":{"input_tokens":5,"output_tokens":6}}',
     True, "application/json"),
    # truncated with NO recoverable usage (books zeros)
    (b'{"id":"z","content":"', b'aaaa', True, "application/json"),
    # decoy: SSE-looking line inside a JSON string value must not
    # flip the parser when the header says JSON
    (b'{"model":"m-4","content":"data: {\\"type\\":\\"message_start\\"}",'
     b'"usage":{"input_tokens":1,"output_tokens":2}}',
     b"", False, "application/json"),
    # invalid utf-8, binary noise, empties
    (b"\xff\xfe\x00garbage", b"\x80\x81", False, None),
    (b"", b"", False, None),
    (b"", b"", True, "text/event-stream"),
    # hostile: huge counts, wrong-typed usage fields, non-dict body
    (b'{"model":"m-5","usage":{"input_tokens":999999999999999,'
     b'"output_tokens":-3,"cache_read_input_tokens":true}}',
     b"", False, "application/json"),
    (b'[1,2,3]', b"", False, "application/json"),
    (b'data: [1,2]\ndata: "str"\ndata: {"type":"message_delta",'
     b'"usage":{"output_tokens":"NaN"}}\n', b"", False,
     "text/event-stream"),
    # deeply-nested brace noise around a real trailing usage object
    (b'{"a":' + b'{"b":' * 200,
     b'"end","usage":{"input_tokens":2,"output_tokens":4,'
     b'"cache_creation_input_tokens":8}}', True, None),
]

_USAGE_KEYS = ("model", "input_tokens", "output_tokens",
               "cache_read_tokens", "cache_creation_tokens")


def _usage_only(verdict: dict) -> dict:
    return {k: verdict[k] for k in _USAGE_KEYS}


# ---------------------------------------------------------------------------
# helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_jail():
    """A dedicated real-worker jail, torn down after the test."""
    jail = usage_scan_jail.UsageScanJail()
    jail.start()
    yield jail
    jail.stop()


@pytest.fixture
def reset_singleton():
    usage_scan_jail._reset_for_tests()
    yield
    usage_scan_jail._reset_for_tests()


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


def _decode_request(payload: bytes) -> "tuple[bytes, bytes, bool, str | None]":
    head_len, tail_len, ct_len, flags = REQ_META.unpack(
        payload[:REQ_META.size])
    off = REQ_META.size
    ct = payload[off:off + ct_len].decode("utf-8") if ct_len else None
    off += ct_len
    head = payload[off:off + head_len]
    tail = payload[off + head_len:off + head_len + tail_len]
    return head, tail, bool(flags & 0x01), ct


# A responder receives (sock, req_id, payload) and either handles the
# reply itself via the socket or returns False to close it (crash).
_Responder = Callable[[socket.socket, int, bytes], bool]


def _honest_responder(sock: socket.socket, req_id: int,
                      payload: bytes) -> bool:
    head, tail, truncated, ct = _decode_request(payload)
    verdict = scan_usage(head, tail, truncated=truncated, content_type=ct)
    _send_frame(sock, req_id, json.dumps(verdict).encode("utf-8"))
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


def _failing_subprocess() -> types.SimpleNamespace:
    """A subprocess stand-in whose Popen always fails, counting calls."""
    calls = {"n": 0}

    def popen(argv: list, **kwargs: object) -> None:
        calls["n"] += 1
        raise OSError("no fork for you")
    ns = types.SimpleNamespace(
        Popen=popen,
        DEVNULL=subprocess.DEVNULL,
        TimeoutExpired=subprocess.TimeoutExpired,
    )
    ns.calls = calls
    return ns


def _fake_jail(monkeypatch, ready: "dict | None",
               responder: _Responder) -> usage_scan_jail.UsageScanJail:
    monkeypatch.setattr(usage_scan_jail, "subprocess",
                        _fake_subprocess(ready, responder))
    return usage_scan_jail.UsageScanJail()


_READY_OK = {"ready": True, "landlock": True, "pid": -1}
_REF = (_JSON_BODY, b"", False, "application/json")


def _scan(jail: usage_scan_jail.UsageScanJail,
          entry: "tuple[bytes, bytes, bool, str | None]") -> dict:
    head, tail, truncated, ct = entry
    return jail.scan(head, tail, truncated=truncated, content_type=ct)


# ---------------------------------------------------------------------------
# differential equivalence (real worker)
# ---------------------------------------------------------------------------


class TestDifferentialEquivalence:

    def test_jailed_verdicts_match_pure_core_over_corpus(self, fresh_jail):
        """For every corpus window the jailed round-trip must return
        the exact dict the pure core returns — model and all four
        counts identical, scan_failed false."""
        for entry in CORPUS:
            head, tail, truncated, ct = entry
            expected = scan_usage(head, tail, truncated=truncated,
                                  content_type=ct)
            # The one deliberate parent-side divergence from the pure
            # core: astronomical counts are clamped before booking
            # (see _MAX_TOKEN_COUNT — hostile-upstream numbers must
            # not blow up budget arithmetic).
            for key in ("input_tokens", "output_tokens",
                        "cache_read_tokens", "cache_creation_tokens"):
                expected[key] = min(expected[key],
                                    usage_scan_jail._MAX_TOKEN_COUNT)
            got = _scan(fresh_jail, entry)
            assert got["scan_failed"] is False
            assert _usage_only(got) == expected, (
                f"jailed verdict diverged for {head[:60]!r}: "
                f"{_usage_only(got)!r} != {expected!r}"
            )

    def test_verdicts_carry_the_serving_tier(self, fresh_jail):
        got = _scan(fresh_jail, _REF)
        assert got["usage_scan_tier"] in (
            usage_scan_jail.TIER_JAIL_LANDLOCK,
            usage_scan_jail.TIER_JAIL_NO_LANDLOCK,
        )
        assert got["usage_scan_tier"] == fresh_jail.tier

    def test_oversized_request_books_failed_never_truncates(
        self, fresh_jail,
    ):
        """A frame-budget violation is OUR bug (the relay caps its
        windows below it) — it books failed loudly rather than
        silently truncating what gets scanned."""
        got = fresh_jail.scan(b"x" * (MAX_FRAME_PAYLOAD + 1), b"",
                              truncated=False, content_type=None)
        assert got["scan_failed"] is True
        assert _usage_only(got) == scan_usage(b"", b"", truncated=False,
                                              content_type=None)
        # jail recovers on the next scan
        assert _scan(fresh_jail, _REF)["scan_failed"] is False


# ---------------------------------------------------------------------------
# crash isolation
# ---------------------------------------------------------------------------


class TestCrashIsolation:

    def test_worker_killed_between_scans_respawns_transparently(
        self, fresh_jail,
    ):
        assert _scan(fresh_jail, _REF)["scan_failed"] is False
        first_pid = fresh_jail._proc.pid
        fresh_jail._proc.kill()
        fresh_jail._proc.wait(timeout=10)
        got = _scan(fresh_jail, _REF)
        assert got["scan_failed"] is False
        assert _usage_only(got) == scan_usage(
            _REF[0], _REF[1], truncated=_REF[2], content_type=_REF[3])
        assert fresh_jail._proc.pid != first_pid

    def test_worker_dying_on_a_scan_books_failed_never_reparses(
        self, monkeypatch,
    ):
        """Poison input costs THAT scan a failed verdict; the bytes are
        never handed to an in-process parser and the next scan is
        served by a fresh worker."""
        poison = b"POISON"
        seen = {"n": 0}

        def responder(sock: socket.socket, req_id: int,
                      payload: bytes) -> bool:
            head, _tail, _t, _ct = _decode_request(payload)
            if head == poison:
                return False  # die on the poison scan
            return _honest_responder(sock, req_id, payload)

        jail = _fake_jail(monkeypatch, _READY_OK, responder)

        def sentinel(*_a: object, **_k: object) -> dict:
            seen["n"] += 1
            raise AssertionError("in-process parse of poison bytes")
        monkeypatch.setattr(usage_scan_jail, "scan_usage", sentinel)
        got = jail.scan(poison, b"", truncated=False, content_type=None)
        assert got["scan_failed"] is True
        assert seen["n"] == 0
        monkeypatch.setattr(usage_scan_jail, "scan_usage", scan_usage)
        assert _scan(jail, _REF)["scan_failed"] is False
        jail.stop()


# ---------------------------------------------------------------------------
# parent re-validation (scripted hostile worker)
# ---------------------------------------------------------------------------


def _static_verdict_responder(verdict_bytes: bytes,
                              req_id_delta: int = 0,
                              declared_len: "int | None" = None,
                              ) -> _Responder:
    def responder(sock: socket.socket, req_id: int,
                  payload: bytes) -> bool:
        _send_frame(sock, (req_id + req_id_delta) & 0xFFFFFFFF,
                    verdict_bytes, declared_len=declared_len)
        return True
    return responder


_HONEST_COUNTS = {"input_tokens": 1, "output_tokens": 2,
                  "cache_read_tokens": 0, "cache_creation_tokens": 0}


class TestParentRevalidation:

    @pytest.mark.parametrize("verdict", [
        b"not json at all",
        b"[1, 2, 3]",
        b'"just a string"',
        json.dumps({"model": 5, **_HONEST_COUNTS}).encode(),
        json.dumps({"model": None, **{**_HONEST_COUNTS,
                                      "input_tokens": True}}).encode(),
        json.dumps({"model": None, **{**_HONEST_COUNTS,
                                      "output_tokens": -1}}).encode(),
        json.dumps({"model": None, **{**_HONEST_COUNTS,
                                      "cache_read_tokens": "7"}}).encode(),
        json.dumps({"model": None, "input_tokens": 1}).encode(),  # missing
    ])
    def test_contract_violations_kill_worker_and_book_failed(
        self, monkeypatch, verdict,
    ):
        jail = _fake_jail(monkeypatch, _READY_OK,
                          _static_verdict_responder(verdict))
        got = _scan(jail, _REF)
        assert got["scan_failed"] is True
        assert _usage_only(got)["input_tokens"] == 0
        assert jail._proc is None  # killed
        jail.stop()

    def test_id_desync_kills_worker(self, monkeypatch):
        jail = _fake_jail(monkeypatch, _READY_OK, _static_verdict_responder(
            json.dumps({"model": None, **_HONEST_COUNTS}).encode(),
            req_id_delta=1))
        assert _scan(jail, _REF)["scan_failed"] is True
        assert jail._proc is None
        jail.stop()

    def test_oversized_declared_frame_kills_worker(self, monkeypatch):
        jail = _fake_jail(monkeypatch, _READY_OK, _static_verdict_responder(
            json.dumps({"model": None, **_HONEST_COUNTS}).encode(),
            declared_len=MAX_FRAME_PAYLOAD + 1))
        assert _scan(jail, _REF)["scan_failed"] is True
        assert jail._proc is None
        jail.stop()

    def test_pre_queued_frame_is_refused_before_send(self, monkeypatch):
        """A worker that answers and pre-queues an extra frame for the
        next scan is caught by the pre-send silence check."""
        def responder(sock: socket.socket, req_id: int,
                      payload: bytes) -> bool:
            _honest_responder(sock, req_id, payload)
            _send_frame(sock, 12345,
                        json.dumps({"model": "forged",
                                    **_HONEST_COUNTS}).encode())
            return True
        jail = _fake_jail(monkeypatch, _READY_OK, responder)
        assert _scan(jail, _REF)["scan_failed"] is False
        got = _scan(jail, _REF)
        assert got["scan_failed"] is True
        assert got["model"] != "forged"
        jail.stop()

    def test_astronomical_counts_clamped_not_kill_worthy(
        self, monkeypatch,
    ):
        """An honest worker relays hostile-upstream numbers verbatim —
        clamping keeps booking monotone without handing the backend a
        kill/respawn loop."""
        jail = _fake_jail(monkeypatch, _READY_OK, _static_verdict_responder(
            json.dumps({"model": "m", **{**_HONEST_COUNTS,
                                         "input_tokens": 10 ** 15}}).encode()))
        got = _scan(jail, _REF)
        assert got["scan_failed"] is False
        assert got["input_tokens"] == usage_scan_jail._MAX_TOKEN_COUNT
        assert jail._proc is not None  # NOT killed
        jail.stop()

    def test_hostile_model_string_sanitised_and_truncated(
        self, monkeypatch,
    ):
        evil = "\x1b[2Jm" + "a" * 500
        jail = _fake_jail(monkeypatch, _READY_OK, _static_verdict_responder(
            json.dumps({"model": evil, **_HONEST_COUNTS}).encode()))
        got = _scan(jail, _REF)
        assert got["scan_failed"] is False
        assert len(got["model"]) <= usage_scan_jail._MAX_MODEL_LEN
        assert "\x1b" not in got["model"]
        assert got["model"] == sanitise_for_terminal(evil)[
            :usage_scan_jail._MAX_MODEL_LEN]
        jail.stop()


# ---------------------------------------------------------------------------
# tier ladder (hermetic fakes — run identically on any runner)
# ---------------------------------------------------------------------------


class TestTierLadder:

    def test_no_landlock_kernel_serves_degraded_with_one_warning(
        self, monkeypatch, caplog,
    ):
        jail = _fake_jail(monkeypatch,
                          {"ready": True, "landlock": False, "pid": -1},
                          _honest_responder)
        with caplog.at_level("WARNING",
                             logger=usage_scan_jail.logger.name):
            for entry in (_REF, _REF, _REF):
                got = _scan(jail, entry)
                assert got["scan_failed"] is False
                assert got["usage_scan_tier"] == (
                    usage_scan_jail.TIER_JAIL_NO_LANDLOCK)
        warnings = [r for r in caplog.records
                    if "WITHOUT Landlock" in r.getMessage()]
        assert len(warnings) == 1
        assert jail.ensure_available() == (
            usage_scan_jail.TIER_JAIL_NO_LANDLOCK)
        jail.stop()

    def test_incapable_kernel_spawn_failure_steps_down_in_process(
        self, monkeypatch, caplog,
    ):
        """Worker can't run + kernel lacks Landlock: scans serve
        in-process (same verdicts as the pure core), exactly one
        warning, sticky after the threshold (no more spawn attempts)."""
        fake = _failing_subprocess()
        monkeypatch.setattr(usage_scan_jail, "subprocess", fake)
        monkeypatch.setattr(usage_scan_jail, "_SPAWN_BACKOFF_BASE_S", 0.0)
        jail = usage_scan_jail.UsageScanJail()
        jail._capable = False  # pin the probe: Landlock-incapable
        with caplog.at_level("WARNING",
                             logger=usage_scan_jail.logger.name):
            for _ in range(6):
                got = _scan(jail, _REF)
                assert got["scan_failed"] is False
                assert got["usage_scan_tier"] == (
                    usage_scan_jail.TIER_IN_PROCESS)
                assert _usage_only(got) == scan_usage(
                    _REF[0], _REF[1], truncated=_REF[2],
                    content_type=_REF[3])
        warnings = [r for r in caplog.records
                    if "in-process" in r.getMessage()
                    and r.levelname == "WARNING"]
        assert len(warnings) == 1  # ONE notice, no spam
        assert jail._sticky_in_process is True
        # Sticky: spawn attempts stopped at the step-down threshold.
        assert fake.calls["n"] == usage_scan_jail._STEPDOWN_AFTER_FAILURES
        assert jail.ensure_available() == usage_scan_jail.TIER_IN_PROCESS
        assert fake.calls["n"] == usage_scan_jail._STEPDOWN_AFTER_FAILURES
        jail.stop()

    def test_capable_kernel_spawn_failure_fails_closed(
        self, monkeypatch,
    ):
        """Landlock-capable kernel + unspawnable worker: admission
        raises, scans book failed, and the in-process parser is NEVER
        invoked."""
        monkeypatch.setattr(usage_scan_jail, "subprocess",
                            _failing_subprocess())
        monkeypatch.setattr(usage_scan_jail, "_SPAWN_BACKOFF_BASE_S", 0.0)
        jail = usage_scan_jail.UsageScanJail()
        jail._capable = True  # pin the probe: Landlock-capable

        def sentinel(*_a: object, **_k: object) -> dict:
            raise AssertionError("in-process parse on a capable kernel")
        monkeypatch.setattr(usage_scan_jail, "scan_usage", sentinel)
        with pytest.raises(usage_scan_jail.UsageScanJailUnavailable):
            jail.ensure_available()
        for _ in range(4):
            got = _scan(jail, _REF)
            assert got["scan_failed"] is True
        assert jail._sticky_in_process is False
        jail.stop()

    def test_landlock_install_error_fails_closed_via_ready_frame(
        self, monkeypatch,
    ):
        """The child reporting an install failure on a capable kernel
        (ready:false, landlock:true) is the fail-closed arm even when
        the parent never probed."""
        jail = _fake_jail(
            monkeypatch,
            {"ready": False, "landlock": True, "pid": -1,
             "error": "landlock install failed: policy rejected"},
            _honest_responder)
        monkeypatch.setattr(usage_scan_jail, "_SPAWN_BACKOFF_BASE_S", 0.0)
        with pytest.raises(usage_scan_jail.UsageScanJailUnavailable):
            jail.ensure_available()
        assert jail._capable is True  # learned from the ready frame
        got = _scan(jail, _REF)
        assert got["scan_failed"] is True
        assert jail._sticky_in_process is False
        jail.stop()

    def test_spawn_backoff_after_consecutive_failures(self, monkeypatch):
        fake = _failing_subprocess()
        monkeypatch.setattr(usage_scan_jail, "subprocess", fake)
        jail = usage_scan_jail.UsageScanJail()
        jail._capable = True
        with pytest.raises(usage_scan_jail.UsageScanJailUnavailable):
            jail.ensure_available()
        assert fake.calls["n"] == 1
        # Immediately again: backing off — no second spawn attempt.
        with pytest.raises(usage_scan_jail.UsageScanJailUnavailable):
            jail.ensure_available()
        assert fake.calls["n"] == 1
        jail.stop()

    def test_real_worker_reports_landlock_on_capable_kernel(
        self, fresh_jail,
    ):
        from core.sandbox.landlock import check_landlock_available
        if not check_landlock_available():
            pytest.skip("kernel lacks Landlock — hermetic fakes above "
                        "cover the ladder logic")
        assert fresh_jail.landlocked is True
        assert fresh_jail.tier == usage_scan_jail.TIER_JAIL_LANDLOCK


# ---------------------------------------------------------------------------
# recycle
# ---------------------------------------------------------------------------


class TestRecycle:

    def test_worker_recycled_between_roundtrips(
        self, monkeypatch, fresh_jail,
    ):
        monkeypatch.setattr(usage_scan_jail, "_RECYCLE_AFTER_SCANS", 3)
        pids = set()
        for _ in range(7):
            got = _scan(fresh_jail, _REF)
            assert got["scan_failed"] is False  # recycle is invisible
            pids.add(fresh_jail._proc.pid)
        assert len(pids) >= 2  # at least one proactive respawn


# ---------------------------------------------------------------------------
# concurrency
# ---------------------------------------------------------------------------


class TestConcurrency:

    def test_threaded_scans_no_crosstalk(self, fresh_jail):
        errors: "list[str]" = []

        def worker(i: int) -> None:
            body = ('{"model":"m-%d","usage":{"input_tokens":%d,'
                    '"output_tokens":%d}}' % (i, i, i + 1)).encode()
            for _ in range(10):
                got = fresh_jail.scan(body, b"", truncated=False,
                                      content_type="application/json")
                if (got["model"] != f"m-{i}"
                        or got["input_tokens"] != i
                        or got["output_tokens"] != i + 1):
                    errors.append(f"crosstalk for worker {i}: {got}")
        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(1, 6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


# ---------------------------------------------------------------------------
# singleton lifecycle
# ---------------------------------------------------------------------------


class TestSingleton:

    def test_get_is_lazy_and_stable(self, reset_singleton):
        jail = usage_scan_jail.get_usage_scan_jail()
        assert jail._proc is None  # lazy: get() never spawns
        assert usage_scan_jail.get_usage_scan_jail() is jail

    def test_reset_tears_down(self, reset_singleton):
        jail = usage_scan_jail.get_usage_scan_jail()
        usage_scan_jail._reset_for_tests()
        assert jail._stopped is True
        assert usage_scan_jail.get_usage_scan_jail() is not jail


# ---------------------------------------------------------------------------
# startup attribution (real child + in-process child main)
# ---------------------------------------------------------------------------


class TestStartupAttribution:
    """A worker that dies during self-confinement must say where and
    why. Without staged attribution, any startup exception unwinds
    past the ready frame and surfaces to the parent as a bare,
    unattributable EOF ("usage-scan worker closed the socket") with
    the traceback lost to the DEVNULL stderr — a platform where one
    startup step misbehaves becomes an undebuggable failure storm
    (fail-closed 503s on capable kernels, spurious in-process
    step-down on incapable ones)."""

    def test_direct_spawn_ready_frame_with_stderr_captured(self):
        """Spawn the real child exactly as the manager does, but with
        stderr CAPTURED: on any pre-frame death this test's failure
        output carries the child's traceback and exit status — the
        diagnostic breadcrumb the production spawn (rightly)
        discards. Keep this test alive on every platform the suite
        runs on: it is the first responder for "the worker dies on
        platform X and nobody knows why"."""
        from core.config import RaptorConfig

        env = RaptorConfig.get_safe_env()
        env["PYTHONPATH"] = usage_scan_jail._raptor_dir()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        child_argv = [sys.executable]
        if sys.version_info >= (3, 11):
            child_argv.append("-P")
        child_argv += ["-m", "core.llm.dispatcher._usage_scan_child"]

        parent_sock, child_sock = socket.socketpair()
        try:
            proc = subprocess.Popen(
                child_argv + [str(child_sock.fileno())],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(child_sock.fileno(),),
                cwd=usage_scan_jail._raptor_dir(),
                env=env,
            )
        finally:
            child_sock.close()
        frame_id = payload = None
        try:
            parent_sock.settimeout(usage_scan_jail._READY_TIMEOUT_S)
            try:
                header = _recv_exact(parent_sock, FRAME_HEADER.size)
                length, frame_id = FRAME_HEADER.unpack(header)
                payload = json.loads(_recv_exact(parent_sock, length))
            except (OSError, ValueError) as exc:
                try:
                    _, stderr = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    _, stderr = proc.communicate()
                pytest.fail(
                    "worker died before the ready frame: read failed "
                    f"with {exc!r}; exit status {proc.returncode}; "
                    "child stderr:\n"
                    + stderr.decode("utf-8", "backslashreplace"))
            assert frame_id == READY_FRAME_ID
            # ready:false here is a real confinement failure — surface
            # the attributed error (this is exactly the signal the
            # attribution frame exists to carry).
            assert payload.get("ready") is True, (
                f"worker refused to confine: {payload}")
            assert isinstance(payload.get("landlock"), bool)
        finally:
            parent_sock.close()  # EOF -> clean child exit
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)

    def test_startup_exception_reports_stage_in_ready_frame(
        self, monkeypatch,
    ):
        """Any exception in the staged startup region produces an
        attributed ready:false frame (stage + exception class +
        message) and rc 1 — never a silent EOF. Driven in-process:
        child main() runs in this process against one end of a real
        socketpair, with the probe forced to blow up."""
        from core.llm.dispatcher import _usage_scan_child as child_mod
        from core.sandbox import landlock as landlock_mod

        parent_sock, worker_sock = socket.socketpair()
        wfd = worker_sock.detach()  # main() adopts sole ownership
        monkeypatch.setattr(child_mod, "_close_inherited_fds",
                            lambda keep_fd: None)
        monkeypatch.setattr(child_mod, "_SOCK_FD", wfd)

        def boom() -> bool:
            raise RuntimeError("forced by test")

        monkeypatch.setattr(landlock_mod, "check_landlock_available",
                            boom)
        try:
            rc = child_mod.main(["prog", str(wfd)])
            assert rc == 1
            parent_sock.settimeout(5.0)
            header = _recv_exact(parent_sock, FRAME_HEADER.size)
            length, frame_id = FRAME_HEADER.unpack(header)
            payload = json.loads(_recv_exact(parent_sock, length))
            assert frame_id == READY_FRAME_ID
            assert payload["ready"] is False
            assert "startup failed at landlock probe" in payload["error"]
            assert "RuntimeError: forced by test" in payload["error"]
        finally:
            parent_sock.close()

    def test_rlimit_failures_are_best_effort_and_reported(
        self, monkeypatch,
    ):
        """A failing setrlimit no longer kills the worker: every limit
        is still attempted and the failures come back for the ready
        frame (platform rlimit semantics vary; the limits are the belt
        of the floor, not the wall)."""
        from core.llm.dispatcher import _usage_scan_child as child_mod

        attempted: "list[int]" = []

        def flaky(res: int, value: int) -> None:
            attempted.append(res)
            if res == resource.RLIMIT_AS:
                raise ValueError("forced by test")

        monkeypatch.setattr(child_mod, "_set_limit", flaky)
        failures = child_mod._apply_rlimits()
        assert failures == ["as: ValueError: forced by test"]
        assert len(attempted) == 5  # every limit attempted regardless

    def test_parent_warns_on_partially_applied_rlimits(
        self, monkeypatch, caplog,
    ):
        ready = {"ready": True, "landlock": True, "pid": -1,
                 "rlimits_failed": ["as: ValueError: forced by test"]}
        jail = _fake_jail(monkeypatch, ready, _honest_responder)
        with caplog.at_level("WARNING",
                             logger=usage_scan_jail.logger.name):
            jail.start()
        try:
            warned = [r for r in caplog.records
                      if "rlimits only partially" in r.getMessage()]
            assert len(warned) == 1
            assert "as: ValueError: forced by test" in warned[0].getMessage()
        finally:
            jail.stop()

    def test_handshake_eof_reports_worker_exit_code(self, monkeypatch):
        """A worker that dies pre-frame gets its fate quoted in the
        UsageScanJailUnavailable message (exit code / signal / killed),
        captured before the manager's own kill+reap destroys it."""
        real_popen = subprocess.Popen

        def early_exit_popen(argv: list, **kwargs: object) -> subprocess.Popen:
            return real_popen(
                [sys.executable, "-c", "import sys; sys.exit(7)"],
                **kwargs)

        monkeypatch.setattr(
            usage_scan_jail, "subprocess",
            types.SimpleNamespace(
                Popen=early_exit_popen,
                DEVNULL=subprocess.DEVNULL,
                TimeoutExpired=subprocess.TimeoutExpired,
            ))
        jail = usage_scan_jail.UsageScanJail()
        with pytest.raises(
            usage_scan_jail.UsageScanJailUnavailable,
            match=r"closed the socket.*worker exited with code 7",
        ):
            jail.start()
        jail.stop()
