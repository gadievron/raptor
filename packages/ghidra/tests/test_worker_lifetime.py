"""The worker closes its session on the owning handler and joins it."""
import json
from pathlib import Path
import sys
import threading

import pytest

from core.testing.standalone_cli import run_standalone_cli
from packages.ghidra import server_worker


MAIN_LIFETIME = r"""import json, socket, sys, tempfile, threading
from pathlib import Path
from packages.ghidra import server_worker as worker
transport, reason = sys.argv[1:]
session = worker._Session()
events = []
original_close = session.close
def close():
    events.append(('close', threading.get_ident()))
    original_close()
session.close = close
original_handle = worker._handle
def handle(session, request):
    events.append(('op', threading.get_ident()))
    return original_handle(session, request)
worker._handle = handle
worker._Session = lambda: session
ready = threading.Event()
handlers = []
original_handler = worker._HandlerThread
def handler(session):
    owned = original_handler(session)
    handlers.append(owned)
    ready.set()
    return owned
worker._HandlerThread = handler
with tempfile.TemporaryDirectory(prefix='gh-close-') as directory:
    if transport == 'fd':
        client, child = socket.socketpair()
        sys.argv = ['worker', '--socket-fd', str(child.detach()), '--idle-timeout', '1']
    else:
        address = str(Path(directory) / 'worker.sock')
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sys.argv = ['worker', address, '--idle-timeout', '1']
    results = {}
    def serve():
        try: results['rc'] = worker.main()
        except BaseException as error: results['error'] = type(error).__name__
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        assert ready.wait(5), results
        if transport == 'path': client.connect(address)
        client.settimeout(5)
        with client, client.makefile('rwb') as stream:
            stream.write(b'{"id":1,"op":"ping"}\n'); stream.flush()
            assert json.loads(stream.readline())['pong'] is True
            if reason == 'shutdown':
                stream.write(b'{"id":2,"op":"shutdown"}\n'); stream.flush()
                assert json.loads(stream.readline())['bye'] is True
            if reason == 'idle': thread.join(5)
    finally:
        client.close()
        thread.join(5)
    assert not thread.is_alive(), results
    print(json.dumps({'result': results, 'events': events,
                      'handler_alive': handlers[0]._thread.is_alive()}))
"""


@pytest.mark.parametrize('transport', ['fd', 'path'])
@pytest.mark.parametrize('reason', ['shutdown', 'eof', 'idle'])
def test_main_releases_the_handler_and_its_session(transport, reason):
    result = run_standalone_cli(
        [sys.executable, '-c', MAIN_LIFETIME, transport, reason],
        cwd=Path(server_worker.__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout.splitlines()[-1])
    assert observed['result'] == {'rc': 0}, observed
    events = observed['events']
    assert [event[0] for event in events] == ['op', 'close'], observed
    assert events[0][1] == events[1][1], observed
    assert not observed['handler_alive'], observed


def test_handler_close_is_idempotent_and_refuses_later_work(monkeypatch):
    session = server_worker._Session()
    closed_on = []
    original = session.close

    def close():
        closed_on.append(threading.get_ident())
        original()

    monkeypatch.setattr(session, 'close', close)
    handler = server_worker._HandlerThread(session)
    try:
        assert handler.run({'op': 'ping'}) == {'pong': True}
        identity = handler._thread.ident
        handler.close()
        handler.close()
        assert closed_on == [identity]
        assert not handler._thread.is_alive()
        with pytest.raises(RuntimeError, match='handler is closed'):
            handler.run({'op': 'ping'})
    finally:
        handler.close(preserve_error=True)


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('preserve', [False, True])
def test_handler_close_reports_cleanup_errors_without_leaving_a_thread(monkeypatch, error_type, preserve):
    session = server_worker._Session()
    error = error_type('owned close failure')
    original = session.close

    def fail():
        original()
        raise error

    monkeypatch.setattr(session, 'close', fail)
    handler = server_worker._HandlerThread(session)
    try:
        if preserve:
            handler.close(preserve_error=True)
        else:
            with pytest.raises(error_type) as caught:
                handler.close()
            assert caught.value is error
        assert not handler._thread.is_alive()
    finally:
        handler.close(preserve_error=True)


def test_handler_close_waits_for_owned_session_cleanup(monkeypatch):
    session = server_worker._Session()
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = session.close

    def close():
        entered.set()
        assert release.wait(5), 'owned cleanup release not signalled'
        original()

    monkeypatch.setattr(session, 'close', close)
    handler = server_worker._HandlerThread(session)

    def stop():
        handler.close()
        finished.set()

    closer = threading.Thread(target=stop)
    try:
        closer.start()
        assert entered.wait(5), 'session cleanup was not reached'
        assert closer.is_alive()
        assert not finished.is_set()
    finally:
        release.set()
        if closer.ident is not None:
            closer.join(timeout=5)
        handler.close(preserve_error=True)
    assert not closer.is_alive()
    assert not handler._thread.is_alive()
    assert finished.is_set()


def test_main_preserves_a_stream_failure_over_session_cleanup():
    code = r"""import json, socket, sys, threading
from packages.ghidra import server_worker as worker
session = worker._Session()
original = session.close
def fail_close():
    original()
    raise ValueError('owned close failure')
session.close = fail_close
worker._Session = lambda: session
reached = []
def fail_stream(handler, stream):
    reached.append('stream')
    raise OSError('owned stream failure')
worker._serve_stream = fail_stream
parent, child = socket.socketpair()
sys.argv = ['worker', '--socket-fd', str(child.detach())]
try:
    try: worker.main()
    except BaseException as error:
        print(json.dumps({'error': type(error).__name__, 'message': str(error),
                          'reached': reached,
                          'handler_alive': any(t.name == 'ghidra-op-handler' for t in threading.enumerate())}))
finally: parent.close()
"""
    result = run_standalone_cli(
        [sys.executable, '-c', code],
        cwd=Path(server_worker.__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout.splitlines()[-1]) == {
        'error': 'OSError', 'message': 'owned stream failure',
        'reached': ['stream'], 'handler_alive': False,
    }


@pytest.mark.integration
def test_real_jvm_exits_after_handler_session_cleanup():
    pytest.importorskip('jpype')
    code = r"""import json
import jpype
from packages.ghidra import server_worker as worker
original = worker._handle
def boot(session, request):
    if not jpype.isJVMStarted():
        jpype.startJVM(jpype.getDefaultJVMPath(), '-Xmx128m')
    return original(session, request)
worker._handle = boot
handler = worker._HandlerThread(worker._Session())
assert handler.run({'op': 'ping'}) == {'pong': True}
handler.close()
print(json.dumps({'closed': True, 'handler_alive': handler._thread.is_alive()}), flush=True)
"""
    result = run_standalone_cli(
        [sys.executable, '-u', '-c', code],
        cwd=Path(server_worker.__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout.splitlines()[-1]) == {
        'closed': True, 'handler_alive': False,
    }


@pytest.mark.integration
def test_borrowed_session_close_keeps_the_callers_jvm_attachment():
    pytest.importorskip('jpype')
    code = r"""import json
import jpype
from packages.ghidra import server_worker as worker
jpype.startJVM(jpype.getDefaultJVMPath(), '-Xmx128m')
is_attached = jpype.java.lang.Thread.isAttached
before = is_attached()
worker._Session().close()
print(json.dumps({'before': before, 'after': is_attached()}), flush=True)
"""
    result = run_standalone_cli(
        [sys.executable, '-u', '-c', code],
        cwd=Path(server_worker.__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout.splitlines()[-1]) == {'before': True, 'after': True}
