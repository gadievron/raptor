"""Parser queue and transport budgets stay bounded without timing ratios."""

from types import ModuleType
from unittest.mock import Mock

import pytest

from core.sandbox import parser_jail as parser


class QueueLock:
    def __init__(self, clock, *, acquired=True, delay=0):
        self.clock, self.acquired, self.delay = clock, acquired, delay
        self.calls, self.released = [], 0

    def acquire(self, **kwargs):
        self.calls.append(kwargs)
        self.clock[0] += self.delay
        return self.acquired

    def release(self):
        self.released += 1

    def __enter__(self):
        if not self.acquire():
            raise AssertionError("unbounded mutex entry attempted")

    def __exit__(self, *args):
        self.release()


@pytest.fixture
def clock(monkeypatch):
    now = [0.0]
    private = ModuleType("owned_parser_time")
    vars(private).update(vars(parser.time))
    private.monotonic = lambda: now[0]
    monkeypatch.setattr(parser, "time", private)
    monkeypatch.setattr(parser, "_ROUNDTRIP_TIMEOUT_S", 1.0)
    return now


def test_busy_queue_refuses_without_touching_active_worker(clock, monkeypatch):
    jail = parser.ParserJail()
    lock = QueueLock(clock, acquired=False)
    jail._lock = lock
    ensure = Mock(side_effect=AssertionError("another request owns this worker"))
    monkeypatch.setattr(jail, "_ensure_worker_locked", ensure)
    with pytest.raises(parser.ParserJailUnavailable, match="queue"):
        jail.parse(b"owned")
    assert lock.calls == [{"timeout": 1.0}]
    assert lock.released == 0
    ensure.assert_not_called()


def test_queue_time_is_not_added_to_transport_budget(clock, transport, monkeypatch):
    transport._lock = QueueLock(clock, delay=0.75)
    monkeypatch.setattr(transport, "_ensure_worker_locked", lambda: None)
    sock = ExchangeSocket(clock)
    transport._sock = sock
    assert transport.parse(b"owned") == parser.ParsedRequestLine("owned.invalid", 443)
    assert sock.send_timeouts == [min(0.25, parser._IO_WAIT_TICK_S)]
    assert sock.gettimeout() == 99.0
    assert transport._lock.released == 1


def test_expired_queue_budget_does_not_send(clock, monkeypatch):
    jail = parser.ParserJail()
    jail._lock = QueueLock(clock, delay=2.0)
    monkeypatch.setattr(jail, "_ensure_worker_locked", lambda: None)
    transaction = Mock()
    monkeypatch.setattr(jail, "_roundtrip_locked", transaction)
    with pytest.raises(parser.ParserJailUnavailable, match="deadline"):
        jail.parse(b"owned")
    transaction.assert_not_called()
    assert jail._lock.released == 1


class QuietPoll:
    def register(self, *args):
        pass

    def poll(self, *args):
        return []


class ExchangeSocket:
    def __init__(self, clock, *, send_delay=0, reply_delay=0, failure=None):
        self.clock, self.send_delay, self.failure = clock, send_delay, failure
        self.reply_delay = reply_delay
        self.closed = False
        self.timeout = 99.0
        self.send_timeouts = []
        payload = b'{"ok":true,"host":"owned.invalid","port":443}'
        self.data = parser.FRAME_HEADER.pack(len(payload), 17) + payload

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value

    def send(self, data):
        self.send_timeouts.append(self.timeout)
        self.clock[0] += self.send_delay
        if self.failure is not None:
            raise self.failure
        return len(data)

    def close(self):
        self.closed = True

    def recv(self, size):
        if self.reply_delay:
            elapsed = min(self.timeout, self.reply_delay)
            self.clock[0] += elapsed
            self.reply_delay -= elapsed
            if self.reply_delay > 0:
                raise parser.socket.timeout('owned delayed reply')
        data, self.data = self.data[:size], self.data[size:]
        return data


@pytest.fixture
def transport(clock, monkeypatch):
    private = ModuleType("owned_parser_select")
    vars(private).update(vars(parser.select))
    private.poll = QuietPoll
    monkeypatch.setattr(parser, "select", private)
    jail = parser.ParserJail()
    monkeypatch.setattr(jail, "_new_req_id", lambda: 17)
    return jail


def test_send_uses_remaining_deadline_and_restores_timeout(clock, transport, monkeypatch):
    sock = ExchangeSocket(clock)
    transport._sock = sock

    def prepare():
        clock[0] += 0.75
        return 17

    monkeypatch.setattr(transport, "_new_req_id", prepare)
    assert transport._roundtrip_locked(b"owned") == parser.ParsedRequestLine("owned.invalid", 443)
    assert sock.send_timeouts == [min(0.25, parser._IO_WAIT_TICK_S)]
    assert sock.gettimeout() == 99.0


def test_request_preparation_cannot_extend_send_budget(clock, transport, monkeypatch):
    sock = ExchangeSocket(clock)
    transport._sock = sock

    def prepare():
        clock[0] += 2.0
        return 17

    monkeypatch.setattr(transport, "_new_req_id", prepare)
    with pytest.raises(OSError, match="timed out"):
        transport._roundtrip_locked(b"owned")
    assert sock.send_timeouts == []
    assert sock.gettimeout() == 99.0


@pytest.mark.parametrize("failure", [OSError("owned send failure"), KeyboardInterrupt("owned cancel")],
                         ids=["io", "interrupt"])
def test_transport_restores_timeout_on_send_failure(clock, transport, failure):
    sock = ExchangeSocket(clock, failure=failure)
    transport._sock = sock
    with pytest.raises(type(failure)) as caught:
        transport._roundtrip_locked(b"owned")
    assert caught.value is failure
    assert sock.send_timeouts == [min(1.0, parser._IO_WAIT_TICK_S)]
    assert sock.gettimeout() == 99.0


def test_cold_start_uses_its_own_lifecycle_budget(clock, transport, monkeypatch):
    transport._lock = QueueLock(clock, delay=0.75)

    def start():
        clock[0] += 10.0

    monkeypatch.setattr(transport, "_ensure_worker_locked", start)
    sock = ExchangeSocket(clock)
    transport._sock = sock
    assert transport.parse(b"owned") == parser.ParsedRequestLine("owned.invalid", 443)
    assert sock.send_timeouts == [min(0.25, parser._IO_WAIT_TICK_S)]
    assert sock.gettimeout() == 99.0
    assert transport._lock.released == 1


@pytest.mark.parametrize('reply_delay,accepted,finished_at', [(0.1, True, .85), (.5, False, 1.0)])
def test_sliced_waits_keep_the_budget_remaining_after_queueing(clock, transport, monkeypatch, reply_delay, accepted, finished_at):
    transport._lock = QueueLock(clock, delay=.75)
    monkeypatch.setattr(transport, '_ensure_worker_locked', lambda: None)
    sock = ExchangeSocket(clock, reply_delay=reply_delay)
    transport._sock = sock
    result = transport.parse(b'owned')
    if accepted:
        assert result == parser.ParsedRequestLine('owned.invalid', 443)
        assert not sock.closed
    else:
        assert isinstance(result, parser.ParseRefusal)
        assert sock.closed and transport._sock is None
    assert clock[0] == pytest.approx(finished_at)
    assert sock.timeout == 99.0
    assert transport._lock.released == 1
