"""Per-registration proxy event-buffer cap + explicit overflow marker.

The per-sandbox buffers were deliberately uncapped ("grows
independently", ~300 bytes of PARENT memory per event) — an
attacker-paced CONNECT loop grew the orchestrator without bound. The
cap under test bounds each registration's buffer, appends ONE explicit
``buffer_overflow`` marker record on the first trim (a capped buffer
is never silent), counts subsequent trims into the marker, and keeps a
bounded reserve for denial-class events so a flood of allowed CONNECTs
cannot push a later attack signal out of the persisted evidence.

Events are injected through proxy._record directly — no sockets, no
CONNECT handshakes — so the tests are hermetic and fast on any host.
"""

import pytest

import core.sandbox.proxy as proxy_mod


@pytest.fixture(autouse=True)
def _confined_parser_floor(confined_parser_floor: None) -> None:
    """This file pins exact buffer lengths against the cap; on
    Landlock-less hosts the per-registration degraded-floor marker
    would consume a slot and shift every count (see
    confined_parser_floor, conftest)."""


@pytest.fixture
def small_caps(monkeypatch):
    monkeypatch.setattr(proxy_mod, "_SANDBOX_BUFFER_MAX_EVENTS", 5)
    monkeypatch.setattr(proxy_mod,
                        "_SANDBOX_BUFFER_DENIAL_RESERVE", 2)


@pytest.fixture
def proxy():
    p = proxy_mod.EgressProxy(allowed_hosts=set())
    try:
        yield p
    finally:
        p.stop()


def _event(result: str = "allowed", host: str = "h.example") -> dict:
    return {
        "t": 0.0, "host": host, "port": 443,
        "result": result, "reason": None, "resolved_ip": None,
        "lane": "main", "lane_id": None,
        "bytes_c2u": 0, "bytes_u2c": 0, "duration": 0.0,
    }


def _markers(events: list) -> list:
    return [e for e in events if e.get("result") == "buffer_overflow"]


class TestBufferCap:
    def test_below_cap_no_marker(self, small_caps, proxy):
        token = proxy.register_sandbox(caller_label="t")
        for _ in range(5):
            proxy._record(_event())
        events = proxy.unregister_sandbox(token)
        assert len(events) == 5
        assert _markers(events) == []

    def test_cap_trims_with_explicit_marker(self, small_caps, proxy):
        token = proxy.register_sandbox(caller_label="t")
        for i in range(9):
            proxy._record(_event(host=f"h{i}.example"))
        events = proxy.unregister_sandbox(token)
        # 5 buffered + 1 marker; 4 trimmed and counted.
        assert len(events) == 6
        markers = _markers(events)
        assert len(markers) == 1, "marker must be one-shot per buffer"
        m = markers[0]
        assert m["cap"] == 5
        assert m["dropped"] == 4
        assert m["dropped_denials"] == 0
        # The marker rides the normal unregister copy — label stamped
        # like any other event, so persisted consumers see it.
        assert m.get("caller") == "t"

    def test_denial_reserve_survives_allowed_flood(self, small_caps,
                                                   proxy):
        """Flood-then-attack ordering: allowed CONNECTs fill the
        buffer, THEN denials arrive. The denial-class reserve keeps
        them in the evidence."""
        token = proxy.register_sandbox(caller_label="t")
        for _ in range(8):
            proxy._record(_event())
        for i in range(4):
            proxy._record(_event(result="denied_host",
                                 host=f"evil{i}.example"))
        events = proxy.unregister_sandbox(token)
        denied = [e for e in events
                  if e.get("result") == "denied_host"]
        assert len(denied) == 2, (
            "denial reserve (2) must keep post-cap denials — and "
            "stay bounded past the reserve")
        m = _markers(events)[0]
        # 3 allowed trimmed + 2 denials past the reserve.
        assert m["dropped"] == 5
        assert m["dropped_denials"] == 2

    def test_denials_below_cap_unaffected(self, small_caps, proxy):
        token = proxy.register_sandbox(caller_label="t")
        proxy._record(_event(result="denied_host"))
        proxy._record(_event())
        events = proxy.unregister_sandbox(token)
        assert len(events) == 2
        assert _markers(events) == []

    def test_buffers_cap_independently(self, small_caps, proxy):
        """The same event dict fans into several buffers; each caps
        on its own count, so a late registration never inherits an
        earlier one's overflow."""
        tok_a = proxy.register_sandbox(caller_label="a")
        for _ in range(6):
            proxy._record(_event())
        tok_b = proxy.register_sandbox(caller_label="b")
        for _ in range(3):
            proxy._record(_event())
        ev_a = proxy.unregister_sandbox(tok_a)
        ev_b = proxy.unregister_sandbox(tok_b)
        assert len(_markers(ev_a)) == 1
        assert _markers(ev_b) == []
        assert len(ev_b) == 3
        # a: 5 kept + marker; post-marker events counted, and the 3
        # later ones landed only in b.
        assert _markers(ev_a)[0]["dropped"] == 4

    def test_overflow_state_reset_on_reregistration(self, small_caps,
                                                    proxy):
        token = proxy.register_sandbox(caller_label="t")
        for _ in range(7):
            proxy._record(_event())
        proxy.unregister_sandbox(token)
        token2 = proxy.register_sandbox(caller_label="t2")
        proxy._record(_event())
        events = proxy.unregister_sandbox(token2)
        assert len(events) == 1
        assert _markers(events) == []
        # Internal state fully torn down.
        assert proxy._sandbox_buffer_overflow == {}

    def test_marker_result_in_canonical_vocabulary(self):
        assert "buffer_overflow" in proxy_mod._PROXY_EVENT_RESULTS

    def test_production_cap_is_generous(self):
        """Guard against an accidental tightening: the cap must stay
        far above what a legitimate run records (per-CONNECT, not
        per-byte)."""
        assert proxy_mod._SANDBOX_BUFFER_MAX_EVENTS >= 10_000
        assert proxy_mod._SANDBOX_BUFFER_DENIAL_RESERVE >= 1_000
