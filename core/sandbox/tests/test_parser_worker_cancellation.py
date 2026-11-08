"""Owned socket exchanges observe stop without resetting their deadline.

Socket-only cases exercise transport and ownership, not native confinement.
The startup identity suite separately launches the production confined worker.
"""

from contextlib import ExitStack
import socket
import threading
from types import SimpleNamespace

import pytest

from core.sandbox import parser_jail as parser
from core.testing.threads import retiring_threads


@pytest.fixture
def exchange(monkeypatch):
    with ExitStack() as owner:
        parent, peer = socket.socketpair()
        owner.callback(peer.close)
        owner.callback(parent.close)
        parent.settimeout(17)
        jail = parser.ParserJail()
        jail._sock = parent
        monkeypatch.setattr(jail, '_ensure_worker_locked', lambda: None)
        threads, results = [], []
        def release():
            jail._stopped = True
            for sock in (peer, parent):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        owner.enter_context(retiring_threads(threads, release=release, timeout=5))
        def start(call, name):
            done = threading.Event()
            def run():
                try:
                    results.append((name, call(), None))
                except BaseException as error:
                    results.append((name, None, error))
                finally:
                    done.set()
            worker = threading.Thread(target=run, name='owned-parser-' + name)
            threads.append(worker)
            worker.start()
            return done
        yield SimpleNamespace(jail=jail, parent=parent, peer=peer, start=start, results=results)


class ObservedSocket:
    def __init__(self, sock, entered, phase):
        self.sock, self.entered, self.phase = sock, entered, phase
    def __getattr__(self, name):
        return getattr(self.sock, name)
    def recv(self, size, *args):
        if not args and (not self.phase.endswith('body') or size == 2):
            self.entered.set()
        return self.sock.recv(size, *args)
    def send(self, data):
        try:
            return self.sock.send(data)
        except socket.timeout:
            self.entered.set()
            raise
    def sendall(self, data):
        # The old implementation blocks here; the new one tracks send offsets.
        self.entered.set()
        return self.sock.sendall(data)


@pytest.mark.parametrize('phase', ['ready-header', 'ready-body', 'reply-header', 'reply-body', 'send'])
def test_stop_cancels_an_exchange_already_waiting_on_its_peer(exchange, phase):
    jail, peer, parent = exchange.jail, exchange.peer, exchange.parent
    entered = threading.Event()
    jail._sock = ObservedSocket(parent, entered, phase)
    if phase == 'send':
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
    if phase == 'ready-body':
        peer.sendall(parser.FRAME_HEADER.pack(2, parser.READY_FRAME_ID))
    if phase == 'reply-body':
        # A fixed owned request ID keeps this test focused on the body wait.
        jail._new_req_id = lambda: 17
        # Send only after the pre-send unsolicited-data check has completed.
        def reply_header():
            peer.recv(16384)
            peer.sendall(parser.FRAME_HEADER.pack(2, 17))
        exchange.start(reply_header, 'peer')
    def request():
        if phase.startswith('ready'):
            with jail._lock:
                return jail._read_ready_frame(jail._sock)
        return jail.parse(b'x' * parser.MAX_FRAME_PAYLOAD if phase == 'send' else b'owned')
    complete = exchange.start(request, 'request')
    assert entered.wait(2), 'request never reached its socket operation'
    stopped = exchange.start(jail.stop, 'stop')
    assert stopped.wait(2), 'stop waited for the full peer deadline'
    assert complete.wait(2), 'request did not unwind after stop'
    error = next(row[2] for row in exchange.results if row[0] == 'request')
    assert isinstance(error, parser.ParserJailUnavailable), repr(error)
    assert 'stopped' in str(error)
    assert jail._sock is None and jail._proc is None and jail._stopped
    assert not next(row[2] for row in exchange.results if row[0] == 'stop')


class RefusingLock:
    def __init__(self):
        self.calls = []
    def acquire(self, **kwargs):
        self.calls.append(kwargs)
        return False
    def __enter__(self):
        raise AssertionError('unbounded lock entry')
    def __exit__(self, *args):
        raise AssertionError('unacquired lock release')


@pytest.mark.parametrize('operation', ['start', 'stop'])
def test_lifecycle_lock_timeout_keeps_existing_ownership(operation):
    jail = parser.ParserJail()
    lock = RefusingLock()
    proc, sock = object(), object()
    jail._lock, jail._proc, jail._sock = lock, proc, sock
    with pytest.raises(parser.ParserJailUnavailable, match='queue deadline'):
        getattr(jail, operation)()
    assert lock.calls == [{'timeout': parser._READY_TIMEOUT_S}]
    assert jail._proc is proc and jail._sock is sock
    assert jail._stopped is (operation == 'stop')


def test_stopped_jail_refuses_new_work_before_locking():
    jail = parser.ParserJail()
    jail._stopped = True
    jail._lock = RefusingLock()
    for call in (jail.start, lambda: jail.parse(b'owned')):
        with pytest.raises(parser.ParserJailUnavailable, match='stopped'):
            call()
    assert not jail._lock.calls


@pytest.mark.parametrize('operation', ['recv', 'roundtrip'])
@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('restore_type', [OSError, KeyboardInterrupt])
def test_timeout_restoration_preserves_the_primary_failure(exchange, operation, primary_type, restore_type):
    jail, parent = exchange.jail, exchange.parent
    primary, secondary = primary_type('owned I/O failure'), restore_type('owned restoration failure')
    class FaultSocket:
        def gettimeout(self):
            return 17
        def settimeout(self, value):
            parent.settimeout(value)
            if value == 17:
                raise secondary
        def fileno(self):
            return parent.fileno()
        def recv(self, *args):
            raise primary
        def send(self, data):
            raise primary
        def sendall(self, data):
            raise primary
    sock = FaultSocket()
    jail._sock = sock
    with pytest.raises(BaseException) as caught:
        if operation == 'recv':
            parser.ParserJail._recv_exact(sock, 1, deadline=parser.time.monotonic() + 1)
        else:
            jail._roundtrip_locked(b'owned')
    assert type(caught.value) is primary_type
    assert caught.value is primary
    assert parent.gettimeout() == 17


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt])
def test_successful_receive_propagates_restore_only_failure(exchange, failure):
    exchange.peer.sendall(b'x')
    parent = exchange.parent
    secondary = failure('owned restoration failure')
    class FaultSocket:
        def gettimeout(self):
            return 17
        def settimeout(self, value):
            parent.settimeout(value)
            if value == 17:
                raise secondary
        def recv(self, size):
            return parent.recv(size)
    with pytest.raises(BaseException) as caught:
        parser.ParserJail._recv_exact(FaultSocket(), 1, deadline=parser.time.monotonic() + 1)
    assert type(caught.value) is failure
    assert caught.value is secondary
    assert parent.gettimeout() == 17


def test_partial_send_retries_preserve_exact_frame_bytes():
    written, faults = bytearray(), [socket.timeout(), InterruptedError()]
    class ShortSocket:
        def settimeout(self, value):
            assert 0 < value <= parser._IO_WAIT_TICK_S
        def send(self, view):
            if faults:
                raise faults.pop(0)
            part = bytes(view[:3])
            written.extend(part)
            return len(part)
    payload = parser.FRAME_HEADER.pack(5, 17) + b'owned'
    parser.ParserJail._send_exact(ShortSocket(), payload,
                                deadline=parser.time.monotonic() + 1,
                                check_cancel=lambda: None)
    assert written == payload


@pytest.mark.parametrize('progress', [0, -1])
def test_send_requires_positive_progress(progress):
    class StalledSocket:
        def settimeout(self, value):
            pass
        def send(self, view):
            return progress
    with pytest.raises(OSError, match='no progress'):
        parser.ParserJail._send_exact(StalledSocket(), b'owned',
                                    deadline=parser.time.monotonic() + 1)
