"""Parser startup binds its loaded checkout and owns failed acquisitions."""

from contextlib import ExitStack
from pathlib import Path
import socket
import subprocess

import pytest

from core.config import RaptorConfig
from core.sandbox import parser_jail as parser
from core.testing.module_bindings import patch_module_attribute
from core.testing.processes import reap_on_exit
from core.testing.standalone_cli import standalone_cli_env, run_standalone_cli
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def owned_worker(tmp_path, monkeypatch):
    """Register physical handles before production startup can fail."""
    with ExitStack() as owner:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        jail = parser.ParserJail()
        processes, sockets, launches = [], [], []
        original_popen, original_pair = subprocess.Popen, socket.socketpair
        def pair():
            result = original_pair()
            for sock in result:
                sockets.append(sock)
                owner.callback(sock.close)
            return result
        def popen(*args, **kwargs):
            # Keep the production import root and confinement, while owning
            # launcher state and writable directories for the child's lifetime.
            requested = {**kwargs, 'env': dict(kwargs['env'])}
            kwargs['env'] = owner.enter_context(standalone_cli_env(env=kwargs['env']))
            proc = original_popen(*args, **kwargs)
            owner.enter_context(reap_on_exit(proc))
            processes.append(proc)
            launches.append((args, requested))
            return proc
        patch_module_attribute(monkeypatch, parser, 'socket', 'socketpair', pair)
        patch_module_attribute(monkeypatch, parser, 'subprocess', 'Popen', popen)
        owner.callback(jail.stop)
        yield jail, processes, sockets, launches


@pytest.mark.parametrize('ambient', [None, '', 'relative-checkout', '/nonexistent/old-checkout'])
def test_import_root_is_bound_to_loaded_parent(monkeypatch, ambient):
    if ambient is None:
        monkeypatch.delenv('RAPTOR_DIR', raising=False)
    else:
        monkeypatch.setenv('RAPTOR_DIR', ambient)
    assert parser._raptor_dir() == str(Path(parser.__file__).resolve().parents[2])


@pytest.mark.slow
@pytest.mark.parametrize('ambient', ['', 'relative-checkout', '/nonexistent/old-checkout'])
def test_confined_worker_uses_loaded_checkout_despite_stale_configuration(owned_worker, monkeypatch, ambient):
    jail, processes, sockets, launches = owned_worker
    monkeypatch.setenv('RAPTOR_DIR', ambient)
    jail.start()
    result = jail.parse(b'CONNECT owned.invalid:443 HTTP/1.1')
    assert result == parser.ParsedRequestLine('owned.invalid', 443)
    root = str(Path(parser.__file__).resolve().parents[2])
    assert len(launches) == 1
    options = launches[0][1]
    assert options['cwd'] == options['env']['PYTHONPATH'] == options['env']['RAPTOR_DIR'] == root
    assert isinstance(jail.landlocked, bool)
    jail.stop()
    assert all(proc.returncode is not None for proc in processes)
    assert all(sock.fileno() == -1 for sock in sockets)


@pytest.mark.slow
def test_startup_resolves_import_root_once(owned_worker, monkeypatch, tmp_path):
    jail, _, _, launches = owned_worker
    root = str(Path(parser.__file__).resolve().parents[2])
    calls = []
    def resolve():
        calls.append(True)
        return root if len(calls) == 1 else str(tmp_path / 'moved-checkout')
    monkeypatch.setattr(parser, '_raptor_dir', resolve)
    jail.start()
    assert len(calls) == 1
    assert launches[0][1]['cwd'] == launches[0][1]['env']['PYTHONPATH'] == root
    assert jail.parse(b'CONNECT owned.invalid:443 HTTP/1.1').host == 'owned.invalid'


@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt])
def test_spawn_error_remains_primary_when_child_endpoint_close_fails(owned_worker, monkeypatch, primary_type, cleanup_type):
    jail, _, sockets, _ = owned_worker
    pair = parser.socket.socketpair
    primary, secondary = primary_type('owned spawn failure'), cleanup_type('owned child close failure')
    class Child:
        def __init__(self, sock):
            self.sock = sock
        def fileno(self):
            return self.sock.fileno()
        def close(self):
            self.sock.close()
            raise secondary
    def endpoints():
        parent, child = pair()
        return parent, Child(child)
    def fail(*args, **kwargs):
        raise primary
    patch_module_attribute(monkeypatch, parser, 'socket', 'socketpair', endpoints)
    patch_module_attribute(monkeypatch, parser, 'subprocess', 'Popen', fail)
    expected = parser.ParserJailUnavailable if primary_type is OSError else KeyboardInterrupt
    with pytest.raises(BaseException) as caught:
        jail.start()
    assert isinstance(caught.value, expected)
    assert (caught.value.__cause__ if primary_type is OSError else caught.value) is primary
    assert any('Secondary stream cleanup failure' in note for note in getattr(caught.value, '__notes__', ()))
    assert jail._proc is None and jail._sock is None
    assert all(sock.fileno() == -1 for sock in sockets)


@pytest.mark.slow
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt])
def test_child_endpoint_close_failure_retires_started_worker(owned_worker, monkeypatch, cleanup_type):
    jail, processes, sockets, _ = owned_worker
    pair = parser.socket.socketpair
    secondary = cleanup_type('owned child close failure')
    class Child:
        def __init__(self, sock):
            self.sock = sock
        def fileno(self):
            return self.sock.fileno()
        def close(self):
            self.sock.close()
            raise secondary
    def endpoints():
        parent, child = pair()
        return parent, Child(child)
    patch_module_attribute(monkeypatch, parser, 'socket', 'socketpair', endpoints)
    expected = parser.ParserJailUnavailable if cleanup_type is OSError else KeyboardInterrupt
    with pytest.raises(BaseException) as caught:
        jail.start()
    assert isinstance(caught.value, expected)
    assert len(processes) == 1 and processes[0].returncode is not None
    assert jail._proc is None and jail._sock is None
    assert all(sock.fileno() == -1 for sock in sockets)


@pytest.mark.slow
def test_stop_prevents_a_ready_worker_being_committed_after_shutdown(owned_worker, monkeypatch):
    import threading
    from core.testing.threads import retiring_threads
    jail, processes, _, _ = owned_worker
    ready, release, stopped, started = (threading.Event() for _ in range(4))
    original_ready = jail._read_ready_frame
    results, threads = {}, []
    def hold_ready(sock):
        frame = original_ready(sock)  # actual production confinement handshake
        ready.set()
        release.wait()
        return frame
    monkeypatch.setattr(jail, '_read_ready_frame', hold_ready)
    def run(name, call, done):
        try:
            results[name] = call()
        except BaseException as error:
            results[name] = error
        finally:
            done.set()
    with retiring_threads(threads, release=release.set, timeout=5):
        worker = threading.Thread(target=run, args=('start', jail.start, started), name='owned-parser-start')
        threads.append(worker)
        worker.start()
        assert ready.wait(10), 'worker never completed its real confinement handshake'
        # Shorten only the lock-contention test after native startup is done;
        # restore the normal reap budget before releasing the ready callback.
        with monkeypatch.context() as patch:
            patch.setattr(parser, '_READY_TIMEOUT_S', .1)
            closer = threading.Thread(target=run, args=('stop', jail.stop, stopped), name='owned-parser-stop')
            threads.append(closer)
            closer.start()
            assert stopped.wait(2), 'stop blocked behind a held startup callback'
            assert isinstance(results['stop'], parser.ParserJailUnavailable)
            assert jail._stopped
        release.set()
        assert started.wait(5), 'startup did not retire its uncommitted worker'
    assert isinstance(results['start'], parser.ParserJailUnavailable)
    assert jail._spawn_failures == 0
    assert jail._proc is None and jail._sock is None
    assert len(processes) == 1 and processes[0].returncode is not None


@pytest.mark.slow
def test_native_worker_keeps_an_unrelated_owned_file_unreadable(owned_worker, monkeypatch, tmp_path):
    from core.sandbox.landlock import check_landlock_available
    if not check_landlock_available():
        pytest.skip('native Landlock read confinement unavailable')
    jail, _, _, _ = owned_worker
    forbidden = tmp_path / 'unrelated-owned-data'
    forbidden.write_text('owned read-denial witness')
    assert forbidden.read_text() == 'owned read-denial witness'
    original_popen = parser.subprocess.Popen
    bootstrap = f'''
import errno, os, sys
from core.sandbox import _parser_jail_child as child
original_parse = child.parse_connect_request_line
def checked_parse(raw):
    try:
        fd = os.open({str(forbidden)!r}, os.O_RDONLY)
    except PermissionError as error:
        assert error.errno in (errno.EACCES, errno.EPERM)
    else:
        os.close(fd)
        raise AssertionError('worker read an unrelated owned file')
    return original_parse(raw)
child.parse_connect_request_line = checked_parse
raise SystemExit(child.main(['worker', sys.argv[1]]))
'''
    def with_read_witness(argv, **kwargs):
        # The production child main still installs its actual confinement;
        # only the owned parser callback adds a read-denial observation.
        return original_popen([argv[0], '-P', '-c', bootstrap, argv[-1]], **kwargs)
    patch_module_attribute(monkeypatch, parser, 'subprocess', 'Popen', with_read_witness)
    jail.start()
    assert jail._landlocked is True
    assert jail.parse(b'CONNECT owned.invalid:443 HTTP/1.1') == parser.ParsedRequestLine('owned.invalid', 443)


@pytest.mark.parametrize('marker', sorted(RaptorConfig.TARGET_ENV_STRIP_SET))
def test_worker_launch_removes_dispatch_markers_without_mutating_safe_env(monkeypatch, marker):
    from core.config import RaptorConfig
    root = str(Path(parser.__file__).resolve().parents[2])
    safe = {'PATH': '/usr/bin:/bin', 'LANG': 'C', marker: 'test-only-marker'}
    before = dict(safe)
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', staticmethod(lambda: safe))
    argv, env = parser._worker_launch(root)
    assert safe == before
    assert marker not in env or (marker == 'RAPTOR_DIR' and env[marker] == root)
    assert env['PATH'] == '/usr/bin:/bin'
    assert env['LANG'] == 'C'
    assert env['PYTHONPATH'] == env['RAPTOR_DIR'] == root
    assert '-s' in argv[:argv.index('-m')]


@pytest.mark.slow
def test_confined_worker_launch_has_no_dispatch_authority(owned_worker, monkeypatch):
    from core.config import RaptorConfig
    jail, _, _, launches = owned_worker
    safe = RaptorConfig.get_safe_env()
    safe.update({name: 'test-only-marker' for name in RaptorConfig.TARGET_ENV_STRIP_SET})
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', staticmethod(lambda: dict(safe)))
    jail.start()
    assert jail.parse(b'CONNECT owned.invalid:443 HTTP/1.1') == parser.ParsedRequestLine('owned.invalid', 443)
    args, options = launches[0]
    assert (set(options['env']) & RaptorConfig.TARGET_ENV_STRIP_SET) == {'RAPTOR_DIR'}
    assert '-s' in args[0][:args[0].index('-m')]


@pytest.mark.slow
def test_worker_interpreter_disables_user_site(tmp_path):
    import json
    root = str(Path(parser.__file__).resolve().parents[2])
    argv, env = parser._worker_launch(root)
    probe = "import json, site, sys; print(json.dumps([sys.flags.no_user_site, site.ENABLE_USER_SITE, sys.flags.safe_path]))"
    result = run_standalone_cli(
        [*argv[:argv.index('-m')], '-c', probe], env=env, cwd=tmp_path,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [1, False, True]
