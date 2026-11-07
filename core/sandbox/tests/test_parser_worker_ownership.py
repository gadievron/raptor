"""Parser worker ownership survives failed cleanup and interrupted requests."""

from types import ModuleType
from unittest.mock import Mock

import pytest

from core.sandbox import parser_jail as parser
from core.testing.module_state import isolated_module_state
from core.testing.state_isolation import pin_user_state_dirs


REQUEST = b"CONNECT owned.invalid:443 HTTP/1.1"


class Cancelled(BaseException):
    pass


@pytest.fixture
def worker(tmp_path, monkeypatch, request):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    jail = parser.ParserJail()
    handles = []

    def finish():
        try:
            jail.stop()
        finally:
            # Retain an independent test-owned handle even if a regression
            # drops production ownership. Tests never abandon their child.
            for proc in handles:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)

    request.addfinalizer(finish)
    jail.start()
    handles.append(jail._proc)
    return jail, handles


def wait_error(kind):
    if kind == "timeout":
        return parser.subprocess.TimeoutExpired("owned worker", 0.1)
    return OSError("owned wait unavailable")


@pytest.mark.parametrize("failure", ["io", "timeout"])
def test_stop_keeps_unconfirmed_child_and_retries(worker, monkeypatch, failure):
    jail, handles = worker
    proc = handles[0]
    sock = jail._sock
    with monkeypatch.context() as patch:
        patch.setattr(proc, "wait", Mock(side_effect=wait_error(failure)))
        for _ in range(3):
            with pytest.raises(parser.ParserJailUnavailable, match="cleanup"):
                jail.stop()
            assert jail._proc is proc
            assert jail._sock is None
            assert jail._reap_pending
    assert sock.fileno() == -1
    jail.stop()
    assert proc.returncode is not None
    assert jail._proc is None and not jail._reap_pending
    jail.stop()


@pytest.mark.parametrize("failure", ["io", "timeout"])
@pytest.mark.parametrize("protocol", [False, True], ids=["io", "protocol"])
def test_replacement_waits_for_previous_child(worker, monkeypatch, failure, protocol):
    jail, handles = worker
    proc = handles[0]
    error = parser._ProtocolError("owned frame failure") if protocol else OSError("owned channel failure")
    with monkeypatch.context() as patch:
        patch.setattr(proc, "wait", Mock(side_effect=wait_error(failure)))
        patch.setattr(jail, "_roundtrip_locked", Mock(side_effect=error))
        spawn = Mock(side_effect=AssertionError("unconfirmed child must not be replaced"))
        patch.setattr(jail, "_spawn_worker_locked", spawn)
        with pytest.raises(parser.ParserJailUnavailable, match="cleanup"):
            jail.parse(REQUEST)
        for _ in range(3):
            with pytest.raises(parser.ParserJailUnavailable, match="cleanup"):
                jail.start()
        spawn.assert_not_called()
        assert jail._proc is proc and jail._sock is None
    jail.start()
    handles.append(jail._proc)
    assert jail._proc is not proc
    assert proc.returncode is not None
    assert jail.parse(REQUEST) == parser.ParsedRequestLine("owned.invalid", 443)


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit, RuntimeError, Cancelled],
                         ids=["interrupt", "exit", "unexpected", "cancel"])
@pytest.mark.parametrize("reap_fails", [False, True], ids=["reaped", "pending"])
def test_interrupted_transaction_is_discarded(worker, monkeypatch, kind, reap_fails):
    jail, handles = worker
    proc, sock = handles[0], jail._sock
    error = kind("owned request interrupted")
    with monkeypatch.context() as patch:
        patch.setattr(jail, "_roundtrip_locked", Mock(side_effect=error))
        if reap_fails:
            patch.setattr(proc, "wait", Mock(side_effect=OSError("owned wait failed")))
        with pytest.raises(kind) as caught:
            jail.parse(REQUEST)
        assert caught.value is error
        assert jail._sock is None
        if reap_fails:
            assert jail._proc is proc and jail._reap_pending
        else:
            assert jail._proc is None
    assert sock.fileno() == -1
    jail.start()
    handles.append(jail._proc)
    assert jail._proc is not proc
    assert proc.returncode is not None
    assert jail.parse(REQUEST) == parser.ParsedRequestLine("owned.invalid", 443)


@pytest.fixture
def singleton(monkeypatch):
    registered = []
    private = ModuleType("owned_parser_atexit")

    def register(callback):
        registered.append(callback)
        return callback

    def unregister(callback):
        registered[:] = [item for item in registered if item != callback]

    private.register, private.unregister = register, unregister
    with isolated_module_state(parser, {"_jail": None}, lock=parser._jail_lock):
        with monkeypatch.context() as patch:
            patch.setattr(parser, "atexit", private)
            try:
                yield registered, patch
            finally:
                # Unit singleton cases use Popen-shaped mocks, no children.
                if parser._jail is not None and parser._jail._proc is not None:
                    parser._jail._proc.wait.side_effect = None
                parser._reset_for_tests()


@pytest.mark.parametrize("kind", [OSError, KeyboardInterrupt], ids=["io", "interrupt"])
def test_exit_registration_precedes_worker_creation(singleton, kind):
    registered, patch = singleton
    error = kind("owned registration failed")
    patch.setattr(parser.atexit, "register", Mock(side_effect=error))
    spawn = Mock()
    patch.setattr(parser.ParserJail, "_spawn_worker_locked", spawn)
    with pytest.raises(kind) as caught:
        parser.get_parser_jail()
    assert caught.value is error
    spawn.assert_not_called()
    assert parser._jail is None and registered == []


@pytest.mark.parametrize("kind", [parser.ParserJailUnavailable, KeyboardInterrupt],
                         ids=["unavailable", "interrupt"])
def test_failed_startup_keeps_cleanup_registration(singleton, kind):
    registered, patch = singleton
    proc = Mock(spec=parser.subprocess.Popen, pid=1234)
    proc.poll.return_value = None
    proc.wait.side_effect = OSError("owned wait unavailable")
    error = kind("owned startup failed")
    spawns = []

    def spawn(jail):
        spawns.append(jail)
        assert registered == [jail.stop]
        jail._proc = proc
        jail._reap_pending = True
        raise error

    patch.setattr(parser.ParserJail, "_spawn_worker_locked", spawn)
    with pytest.raises(kind) as caught:
        parser.get_parser_jail()
    assert caught.value is error
    owner = parser._jail
    assert owner is not None and owner._proc is proc
    assert registered == [owner.stop]
    with pytest.raises(parser.ParserJailUnavailable):
        parser.get_parser_jail()
    assert len(spawns) == 1
    with pytest.raises(parser.ParserJailUnavailable):
        parser._reset_for_tests()
    assert parser._jail is owner and registered == [owner.stop]
    proc.wait.side_effect = None
    parser._reset_for_tests()
    assert parser._jail is None and registered == []


def test_startup_without_child_rolls_back_singleton(singleton):
    registered, patch = singleton
    patch.setattr(parser.ParserJail, "_spawn_worker_locked",
                  Mock(side_effect=parser.ParserJailUnavailable("owned spawn refused")))
    with pytest.raises(parser.ParserJailUnavailable):
        parser.get_parser_jail()
    assert parser._jail is None and registered == []


@pytest.mark.parametrize("kind", [parser._ProtocolError, KeyboardInterrupt, SystemExit],
                         ids=["handshake", "interrupt", "exit"])
def test_real_startup_failure_retains_unconfirmed_child(tmp_path, monkeypatch, request, kind):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    jail = parser.ParserJail()
    handles = []

    def finish():
        try:
            jail.stop()
        finally:
            for proc in handles:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)

    request.addfinalizer(finish)
    original = kind("owned handshake interrupted")

    def unconfirmed(proc):
        handles.append(proc)
        return False

    with monkeypatch.context() as patch:
        patch.setattr(jail, "_read_ready_frame", Mock(side_effect=original))
        patch.setattr(jail, "_reap_locked", unconfirmed)
        expected = parser.ParserJailUnavailable if kind is parser._ProtocolError else kind
        with pytest.raises(expected) as caught:
            jail.start()
        if kind is not parser._ProtocolError:
            assert caught.value is original
        assert len(handles) == 1
        assert jail._proc is handles[0] and jail._reap_pending
        assert jail._sock is None
    jail._next_spawn_attempt = 0.0
    jail.start()
    handles.append(jail._proc)
    assert handles[0].returncode is not None
    assert jail._proc is not handles[0]
    assert jail.parse(REQUEST) == parser.ParsedRequestLine("owned.invalid", 443)


@pytest.mark.parametrize("protocol", [False, True], ids=["io", "protocol"])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt], ids=["report-error", "report-cancel"])
def test_reporting_failure_cannot_reuse_invalid_worker(worker, monkeypatch, protocol, kind):
    jail, handles = worker
    proc, sock = handles[0], jail._sock
    failure = parser._ProtocolError("owned protocol failure") if protocol else OSError("owned transport failure")
    reporting = kind("owned reporting interrupted")
    logger = Mock(spec=parser.logger)
    logger.warning.side_effect = reporting
    with monkeypatch.context() as patch:
        patch.setattr(jail, "_roundtrip_locked", Mock(side_effect=failure))
        patch.setattr(parser, "logger", logger)
        with pytest.raises(kind) as caught:
            jail.parse(REQUEST)
        assert caught.value is reporting
        assert jail._proc is None and jail._sock is None
        assert proc.returncode is not None and sock.fileno() == -1
    jail.start()
    handles.append(jail._proc)
    assert jail._proc is not proc
    assert jail.parse(REQUEST) == parser.ParsedRequestLine("owned.invalid", 443)
