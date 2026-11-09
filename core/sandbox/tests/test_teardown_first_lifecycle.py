"""Owned subprocesses retire sweeper-first on timeout, cancellation and I/O loss."""

import os
import select
import subprocess
import sys
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox import context as ctx
from core.sandbox import _spawn as spawn
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import scoped_function_imports


class Cancelled(BaseException):
    pass


@pytest.fixture
def owned():
    processes, streams, descriptors = [], [], []
    holder = [None]
    death_w = None
    def retire(proc, kill, wait):
        try:
            if proc.returncode is None:
                kill()
        finally:
            wait(timeout=5)
    def cleanup():
        # Register cleanup before setup can acquire anything. ExitStack
        # retires siblings even if one owned close/wait itself fails.
        with ExitStack() as finish:
            for fd in descriptors:
                finish.callback(os.close, fd)
            for stream in streams:
                finish.callback(stream.close)
            for args in processes:
                finish.callback(retire, *args)
            if holder[0] is not None:
                finish.callback(spawn.close_death_w, holder[0])
    with ExitStack() as owners, pytest.MonkeyPatch.context() as setup:
        owners.callback(cleanup)
        death_r, death_w = spawn.open_death_pipe()
        holder[0] = death_w
        descriptors.append(death_r)
        configure = [lambda proc: None]
        mode = ["death"]
        real_popen = subprocess.Popen
        state = SimpleNamespace(holder=holder, processes=processes, configure=configure,
                                mode=mode, death_w=death_w)
        def create(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            processes.append((proc, proc.kill, proc.wait))
            streams.extend(s for s in (proc.stdin, proc.stdout, proc.stderr) if s is not None)
            poller = select.poll()
            poller.register(state.ready_r, select.POLLIN)
            assert poller.poll(5000), "owned child did not report startup"
            assert os.read(state.ready_r, 1) == b"R"
            configure[0](proc)
            return proc
        patch_module_attribute(setup, ctx, "subprocess", "Popen", create)
        setup.setattr(ctx, "_TEARDOWN_SWEEP_GRACE_S", 1.0)
        setup.setattr(ctx, "_TEARDOWN_KILL_GRACE_S", 2.0, raising=False)
        def invoke(*, max_capture_bytes=None, **options):
            ready_r, ready_w = os.pipe()
            descriptors.extend([ready_r, ready_w])
            state.ready_r = ready_r
            # The fixture is a plain owned child exercising this executor's
            # lifecycle. No namespace/policy claim is made for these tests.
            script = (
                "import os,sys\n"
                f"os.write({ready_w}, b'R')\n"
                "os.write(1,b'prefix')\n"
                + (f"os.read({death_r},1)\n" if mode[0] == "death" else
                   "sys.stdin.buffer.read()\n" if mode[0] == "stdin" else
                   "os.read(0,1)\n" if mode[0] == "park" else "")
                + "os.write(1,b'suffix')\nos.write(2,b'err')\n"
                + ("sys.exit(7)\n" if mode[0] == "exit7" else "")
            )
            if mode[0] == "park":
                setup.setattr(ctx, "_TEARDOWN_SWEEP_GRACE_S", 0.02)
                # A test-owned unread pipe holds the child independently
                # of the death channel, modelling a stuck sweeper.
                park_r, park_w = os.pipe()
                descriptors.extend([park_r, park_w])
                options.setdefault("stdin", park_r)
            kwargs = dict(capture_output=True, timeout=None,
                          pass_fds=(death_r, ready_w),
                          env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
            kwargs.update(options)
            state.kwargs = kwargs
            return ctx._run_teardown_first_timeout(
                [sys.executable, "-P", "-c", script], kwargs, holder, True,
                max_capture_bytes=max_capture_bytes)
        state.invoke = invoke
        yield state


@pytest.fixture
def monkeypatch(owned):
    # Faults undo before the owning process fixture retires its handles.
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def fault_once(owned, monkeypatch, error):
    def configure(proc):
        real = proc.communicate
        count = 0
        def communicate(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 1:
                raise error
            return real(*args, **kwargs)
        monkeypatch.setattr(proc, "communicate", communicate)
    owned.configure[0] = configure


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, SystemExit, Cancelled, OSError])
@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_every_communication_failure_signals_and_reaps_before_propagating(owned, monkeypatch, kind, text):
    error = kind("owned communicate failure")
    fault_once(owned, monkeypatch, error)
    with pytest.raises(kind) as raised:
        owned.invoke(text=text)
    assert raised.value is error
    proc = owned.processes[0][0]
    assert proc.returncode == 0, "death-EOF watcher was killed before its normal teardown"
    assert owned.holder == [None]
    assert owned.death_w not in spawn._LIVE_DEATH_W
    assert all(s is None or s.closed for s in (proc.stdin, proc.stdout, proc.stderr))


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_timeout_keeps_identity_budget_and_byte_output_after_graceful_retirement(owned, monkeypatch, text):
    error = subprocess.TimeoutExpired(["owned request"], 123, output=b"prefix", stderr=None)
    fault_once(owned, monkeypatch, error)
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        owned.invoke(text=text)
    assert raised.value is error and error.timeout == 123
    assert error.output == b"prefixsuffix" and error.stderr == b"err"
    assert owned.processes[0][0].returncode == 0


@pytest.mark.parametrize("log_error", [OSError, ValueError], ids=["io", "closed-stream"])
def test_broken_diagnostics_cannot_prevent_forced_kill_and_reap(owned, monkeypatch, log_error):
    owned.mode[0] = "park"
    error = subprocess.TimeoutExpired("owned request", 1, output=b"prefix")
    fault_once(owned, monkeypatch, error)
    logger = ctx.logger
    class LoggerView:
        def __getattr__(self, name):
            return getattr(logger, name)
        def warning(self, *args, **kwargs):
            raise log_error("owned broken log stream")
    monkeypatch.setattr(ctx, "logger", LoggerView())
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        owned.invoke()
    assert raised.value is error
    assert owned.processes[0][0].returncode == -9


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, OSError])
def test_secondary_drain_failure_preserves_primary_and_still_waits(owned, monkeypatch, kind):
    primary = Cancelled("owned primary cancellation")
    calls = []
    def configure(proc):
        def communicate(*args, **kwargs):
            calls.append(owned.holder[0])
            if len(calls) == 1:
                raise primary
            raise kind("owned cleanup drain failure")
        monkeypatch.setattr(proc, "communicate", communicate)
    owned.configure[0] = configure
    with pytest.raises(Cancelled) as raised:
        owned.invoke()
    assert raised.value is primary and calls == [owned.death_w, None]
    assert owned.processes[0][0].returncode == 0


@pytest.mark.parametrize("kind", [OSError, KeyboardInterrupt])
def test_unconfirmed_wait_retains_the_exact_owned_process_on_primary_error(owned, monkeypatch, kind):
    primary = RuntimeError("owned primary")
    def configure(proc):
        monkeypatch.setattr(proc, "communicate", Mock(side_effect=primary))
        monkeypatch.setattr(proc, "wait", Mock(side_effect=kind("owned wait failed")))
    owned.configure[0] = configure
    with pytest.raises(RuntimeError) as raised:
        owned.invoke()
    assert raised.value is primary
    assert owned.holder == [None]
    assert primary.sandbox_cleanup_pending
    assert primary.sandbox_process is owned.processes[0][0]
    assert any("exit unconfirmed" in note for note in primary.__notes__)


def test_escalation_happens_only_after_the_registered_death_pipe_is_consumed(owned, monkeypatch):
    owned.mode[0] = "park"
    primary = RuntimeError("owned primary")
    killed = []
    def configure(proc):
        real = proc.kill
        def kill():
            assert owned.holder == [None]
            assert owned.death_w not in spawn._LIVE_DEATH_W
            killed.append(proc)
            real()
        monkeypatch.setattr(proc, "kill", kill)
    owned.configure[0] = configure
    # Configure both the ordering observer and the initial communicate fault.
    observe = owned.configure[0]
    def configured(proc):
        observe(proc)
        real = proc.communicate
        count = 0
        def communicate(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 1:
                raise primary
            return real(*args, **kwargs)
        monkeypatch.setattr(proc, "communicate", communicate)
    owned.configure[0] = configured
    with pytest.raises(RuntimeError):
        owned.invoke()
    assert killed == [owned.processes[0][0]]


def test_timeout_snapshots_are_cumulative_not_concatenated_or_discarded(owned, monkeypatch):
    owned.mode[0] = "park"
    primary = subprocess.TimeoutExpired("owned", 1, output=b"a", stderr=b"e")
    def configure(proc):
        snapshots = iter([primary,
                          subprocess.TimeoutExpired("owned", 2, output=b"ab", stderr=b"ef"),
                          subprocess.TimeoutExpired("owned", 3, output=b"abc", stderr=b"efg")])
        monkeypatch.setattr(proc, "communicate", lambda *a, **kw: (_ for _ in ()).throw(next(snapshots)))
    owned.configure[0] = configure
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        owned.invoke()
    assert raised.value is primary
    assert primary.output == b"abc" and primary.stderr == b"efg"
    assert owned.processes[0][0].returncode == -9


@pytest.mark.parametrize("options", [
    pytest.param({"capture_output": True, "stdout": subprocess.PIPE}, id="capture-stdout"),
    pytest.param({"capture_output": True, "stderr": subprocess.PIPE}, id="capture-stderr"),
    pytest.param({"input": b"owned", "stdin": subprocess.PIPE}, id="input-stdin"),
])
def test_conflicting_stdio_options_refuse_before_spawning_and_preserve_kwargs(owned, options):
    before = dict(options)
    owned.mode[0] = "exit"
    with pytest.raises(ValueError):
        owned.invoke(**options)
    assert owned.processes == [] and options == before
    assert owned.holder == [owned.death_w]


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_success_preserves_normal_types_and_does_not_mutate_caller_options(owned, text):
    owned.mode[0] = "exit"
    result = owned.invoke(text=text)
    assert result.returncode == 0
    assert result.stdout == ("prefixsuffix" if text else b"prefixsuffix")
    assert result.stderr == ("err" if text else b"err")
    assert owned.kwargs["capture_output"] is True
    assert owned.holder == [owned.death_w]


def test_check_failure_retains_captured_output_after_process_and_stream_cleanup(owned):
    owned.mode[0] = "exit7"
    with pytest.raises(subprocess.CalledProcessError) as raised:
        owned.invoke(check=True)
    assert raised.value.returncode == 7 and raised.value.output == b"prefixsuffix"
    assert owned.processes[0][0].returncode == 7


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_wrong_input_type_cannot_leak_a_started_process(owned, text):
    owned.mode[0] = "stdin"
    with pytest.raises(AttributeError if text else TypeError):
        owned.invoke(input=b"data" if text else "data", text=text)
    assert owned.processes[0][0].returncode is not None
    assert owned.holder == [None]


def test_decode_failure_still_closes_the_owned_capture_streams(owned, monkeypatch):
    primary = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "owned invalid output")
    fault_once(owned, monkeypatch, primary)
    with pytest.raises(UnicodeDecodeError) as raised:
        owned.invoke(text=True)
    assert raised.value is primary and owned.processes[0][0].returncode == 0


def test_timeout_without_capture_preserves_absent_output_streams(owned, monkeypatch):
    primary = subprocess.TimeoutExpired("owned", 1)
    fault_once(owned, monkeypatch, primary)
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        owned.invoke(capture_output=False)
    assert raised.value is primary and primary.output is None and primary.stderr is None


@pytest.mark.parametrize("fields", [["stdout"], ["stderr"], ["stdout", "stderr"]],
                         ids=["stdout-none", "stderr-none", "both-none"])
def test_explicit_none_streams_still_allow_capture(owned, fields):
    owned.mode[0] = "exit"
    result = owned.invoke(**dict.fromkeys(fields))
    assert result.stdout == b"prefixsuffix" and result.stderr == b"err"


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_valid_input_is_delivered_and_owned_stdin_is_closed(owned, text):
    owned.mode[0] = "stdin"
    result = owned.invoke(input="data" if text else b"data", text=text)
    assert result.stdout == ("prefixsuffix" if text else b"prefixsuffix")
    assert owned.processes[0][0].stdin.closed


@pytest.mark.parametrize("field", ["stdout", "stderr"])
def test_caller_owned_output_files_remain_open(owned, tmp_path, field):
    owned.mode[0] = "exit"
    with (tmp_path / "output").open("wb+") as output:
        result = owned.invoke(capture_output=False, **{field: output})
        assert result.returncode == 0 and not output.closed
        output.seek(0)
        assert output.read() == (b"prefixsuffix" if field == "stdout" else b"err")


def test_failed_kill_and_wait_keep_the_owned_process_available_for_retry(owned, monkeypatch):
    owned.mode[0] = "park"
    primary = RuntimeError("owned initial failure")
    fault_once(owned, monkeypatch, primary)
    configure = owned.configure[0]
    def faults(proc):
        configure(proc)
        monkeypatch.setattr(proc, "kill", Mock(side_effect=OSError("owned kill denied")))
    owned.configure[0] = faults
    with pytest.raises(RuntimeError) as raised:
        owned.invoke()
    assert raised.value is primary
    assert owned.holder == [None] and owned.processes[0][0].kill.call_count == 1
    assert primary.sandbox_cleanup_pending
    assert primary.sandbox_process is owned.processes[0][0]
    assert any("killing sweeper" in note for note in primary.__notes__)


def test_kill_racing_exit_does_not_skip_the_final_reap(owned, monkeypatch):
    owned.mode[0] = "park"
    primary = RuntimeError("owned initial failure")
    fault_once(owned, monkeypatch, primary)
    configure = owned.configure[0]
    def faults(proc):
        configure(proc)
        real = proc.kill
        def kill():
            real()
            raise ProcessLookupError("owned exit raced kill report")
        monkeypatch.setattr(proc, "kill", kill)
    owned.configure[0] = faults
    with pytest.raises(RuntimeError) as raised:
        owned.invoke()
    assert raised.value is primary
    assert owned.processes[0][0].returncode == -9
    assert not primary.sandbox_cleanup_pending


def test_failed_pipe_close_does_not_skip_siblings_and_retains_the_open_owner(owned, monkeypatch):
    primary = RuntimeError("owned initial failure")
    retained = []
    def configure(proc):
        actual = proc.stdout
        class PipeView:
            def __getattr__(self, name):
                return getattr(actual, name)
            def close(self):
                raise OSError("owned pipe close failed")
        view = PipeView()
        retained.append(view)
        proc.stdout = view
        monkeypatch.setattr(proc, "communicate", Mock(side_effect=primary))
    owned.configure[0] = configure
    with pytest.raises(RuntimeError) as raised:
        owned.invoke()
    proc = owned.processes[0][0]
    assert proc.returncode == 0 and proc.stderr.closed
    assert raised.value is primary and primary.sandbox_pipes == tuple(retained)
    assert primary.sandbox_cleanup_pending
    assert not retained[0].closed


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, Cancelled])
def test_final_close_failure_cannot_turn_into_success(owned, monkeypatch, error):
    owned.mode[0] = "done"
    primary = error("owned final pipe close")
    calls = []

    def configure(proc):
        actual = proc.stdout

        class PipeView:
            def __getattr__(self, name):
                return getattr(actual, name)

            def close(self):
                calls.append(actual.closed)
                if actual.closed:
                    raise primary
                actual.close()

        proc.stdout = PipeView()

    owned.configure[0] = configure
    with pytest.raises(error) as raised:
        owned.invoke()
    assert raised.value is primary
    proc = owned.processes[0][0]
    assert proc.returncode == 0
    assert calls[0] is False and calls[1:] == [True, True, True]
    assert proc.stdout.closed and proc.stderr.closed


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, Cancelled])
def test_capped_final_close_retains_the_unclosed_owner(owned, error):
    owned.mode[0] = "done"
    primary = error("owned bounded pipe close")

    def configure(proc):
        actual = proc.stdout

        class PipeView:
            def __getattr__(self, name):
                return getattr(actual, name)

            def close(self):
                raise primary

        proc.stdout = PipeView()

    owned.configure[0] = configure
    with pytest.raises(error) as raised:
        owned.invoke(max_capture_bytes=97)
    proc = owned.processes[0][0]
    assert raised.value is primary
    assert proc.returncode == 0 and proc.stderr.closed
    assert not proc.stdout.closed
    assert primary.sandbox_cleanup_pending
    assert primary.sandbox_pipes == (proc.stdout,)
    assert owned.holder == [None]


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, Cancelled])
def test_check_failure_survives_secondary_pipe_close_failure(owned, monkeypatch, error):
    owned.mode[0] = "exit7"
    secondary = error("owned secondary pipe close")

    def configure(proc):
        real_communicate = proc.communicate
        actual = proc.stdout

        class PipeView:
            def __getattr__(self, name):
                return getattr(actual, name)

            def close(self):
                raise secondary

        def communicate(*args, **kwargs):
            result = real_communicate(*args, **kwargs)
            proc.stdout = PipeView()
            return result

        monkeypatch.setattr(proc, "communicate", communicate)

    owned.configure[0] = configure
    with pytest.raises(subprocess.CalledProcessError) as raised:
        owned.invoke(check=True)
    assert raised.value.returncode == 7
    assert raised.value.stdout == b"prefixsuffix"
    assert raised.value.stderr == b"err"
    assert not raised.value.sandbox_cleanup_pending
    assert any(type(secondary).__name__ in note for note in raised.value.__notes__)
    assert owned.holder == [None]


def test_spawn_failure_does_not_consume_the_callers_death_channel(owned, tmp_path):
    with pytest.raises(FileNotFoundError):
        owned.invoke(cwd=tmp_path / "missing")
    assert owned.processes == [] and owned.holder == [owned.death_w]


def test_interrupted_death_close_cannot_leave_a_consumed_number_for_outer_retry(owned, monkeypatch):
    primary = RuntimeError("owned communication failure")
    fault_once(owned, monkeypatch, primary)
    original = spawn.close_death_w
    calls = []
    def close_then_interrupt(fd):
        calls.append(fd)
        result = original(fd)
        if len(calls) == 1:
            raise Cancelled("owned interrupt after descriptor release")
        return result
    with scoped_function_imports(ctx, ["_finish_teardown_first"],
                                 {"core.sandbox._spawn": spawn}) as imports:
        private = getattr(imports, "core.sandbox._spawn")
        monkeypatch.setattr(private, "close_death_w", close_then_interrupt)
        try:
            with pytest.raises(RuntimeError) as raised:
                owned.invoke()
        finally:
            # Model run()'s outer cleanup. It must never repeat a consumed
            # number, which can already belong to a different resource.
            if owned.holder[0] is not None:
                fd, owned.holder[0] = owned.holder[0], None
                private.close_death_w(fd)
    assert raised.value is primary
    assert calls == [owned.death_w]
    assert owned.processes[0][0].returncode == 0
    assert primary.sandbox_cleanup_pending
