"""Fallback capture bounds retained output while still finishing real I/O."""

from contextlib import ExitStack
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import fcntl
import resource
import select
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import context as ctx
from core.sandbox import _capture as capture
from core.sandbox.tests.capability import requires_landlock
from core.sandbox.python_paths import python_runtime_tool_paths
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def runner(tmp_path):
    records, communicators, streams, descriptors = [], [], [], []
    state = SimpleNamespace(records=records, communicators=communicators,
                            forbid_communicate=True, configure=lambda proc: None, unbounded_calls=0)
    real_popen = subprocess.Popen
    def retire(proc, kill, wait):
        try:
            if proc.returncode is None:
                kill()
        finally:
            wait(5)
    def cleanup():
        with ExitStack() as finish:
            for fd in descriptors:
                finish.callback(os.close, fd)
            for stream in streams:
                finish.callback(stream.close)
            for record in records:
                finish.callback(retire, *record)
    with ExitStack() as owners, pytest.MonkeyPatch.context() as setup:
        owners.callback(cleanup)
        pin_user_state_dirs(setup, tmp_path / "state")
        def create(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            records.append((proc, proc.kill, proc.wait))
            streams.extend(s for s in (proc.stdin, proc.stdout, proc.stderr) if s is not None)
            if state.forbid_communicate:
                def unbounded(*args, **kwargs):
                    state.unbounded_calls += 1
                    raise AssertionError("capped fallback used unbounded Popen.communicate")
                setup.setattr(proc, "communicate", unbounded)
            state.configure(proc)
            return proc
        # run() must also resolve the owned constructor on its private globals:
        # otherwise an old subprocess.run branch would evade the observation.
        setup.setattr(ctx, "subprocess", module_function_view(subprocess, bindings={"Popen": create}))
        class Recording(capture.BoundedCommunicator):
            def __init__(self, cap):
                communicators.append(self)
                super().__init__(cap)
                self.seen = {"stdout": 0, "stderr": 0}
                self.peak = 0
            def _accept(self, label, chunk):
                super()._accept(label, chunk)
                self.seen[label] += len(chunk)
                self.peak = max(self.peak, sum(map(len, self._buffers.values())))
                assert all(len(buf) <= self.cap for buf in self._buffers.values())
        setup.setattr(ctx, "BoundedCommunicator", Recording, raising=False)
        out = tmp_path / "out"
        out.mkdir()
        def execute(program, *, cap=97, native=False, **kwargs):
            options = dict(disabled=not native, target=str(tmp_path), output=str(out), block_network=False)
            if native:
                options["restrict_reads"] = True
                options["tool_paths"] = python_runtime_tool_paths()
            kwargs.setdefault("capture_output", True)
            kwargs.setdefault("timeout", 5)
            kwargs.setdefault("env", {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
            if cap is not None:
                kwargs["max_capture_bytes"] = cap
            with ctx.sandbox(**options) as run:
                return run([os.path.realpath(sys.executable), "-S", "-c", program], **kwargs)
        state.execute, state.setup, state.streams = execute, setup, streams
        state.descriptors, state.out = descriptors, out
        yield state


@pytest.fixture
def monkeypatch(runner):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


FLOOD = "import os\nfor _ in range(128):\n os.write(1,b'o'*65536);os.write(2,b'e'*65536)\n"


@pytest.mark.parametrize("cap", [0, 1, 97, 65536])
@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_output_flood_keeps_only_the_requested_prefix_and_finishes(runner, cap, text):
    result = runner.execute(FLOOD, cap=cap, text=text)
    assert result.returncode == 0
    for label, char in (("stdout", "o"), ("stderr", "e")):
        marker = f"\n[sandbox: {label} capture truncated at {cap} bytes]\n"
        expected = char * cap + marker
        assert getattr(result, label) == (expected if text else expected.encode())
    owner, = runner.communicators
    assert owner.seen == {"stdout": 128 * 65536, "stderr": 128 * 65536}
    assert owner.peak <= 2 * cap
    assert not hasattr(runner.records[0][0], "_fileobj2output")


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_input_and_output_make_progress_together_under_backpressure(runner, text):
    payload = ("data" * 262144) if text else b"data" * 262144
    program = FLOOD + "import sys\ndata=sys.stdin.buffer.read()\nassert data==b'data'*262144\n"
    result = runner.execute(program, input=payload, text=text)
    assert result.returncode == 0
    assert runner.records[0][0].stdin.closed
    assert runner.communicators[0].peak <= 194


@pytest.mark.parametrize("cap", [1, 3, 4, 5])
def test_text_cap_does_not_turn_a_split_utf8_character_into_a_decode_error(runner, cap):
    result = runner.execute("import os\nos.write(1,'é🦕tail'.encode())", cap=cap, text=True)
    prefix = ("é🦕tail".encode()[:cap]).decode("utf-8", errors="ignore")
    marker = f"\n[sandbox: stdout capture truncated at {cap} bytes]\n"
    assert result.stdout == prefix + marker
    assert result.stdout.count("capture truncated") == 1


@pytest.mark.parametrize("encoding,raw,expected,cap", [
    pytest.param("latin-1", b"\xe9" * 8, "é", 3, id="utf8-result-expands"),
    pytest.param("utf-16", "🦕abc".encode("utf-16"), "🦕", 6, id="utf16-prefix"),
    pytest.param("utf-8", b"a\r\nb\rc\n", "a\nb\nc\n", 40, id="universal-newlines"),
])
def test_text_encoding_and_presentation_cap_remain_consistent(runner, encoding, raw, expected, cap):
    result = runner.execute(f"import os\nos.write(1,{raw!r})", cap=cap, text=True, encoding=encoding)
    if len(raw) > cap or len(expected.encode()) > cap:
        assert result.stdout == expected + f"\n[sandbox: stdout capture truncated at {cap} bytes]\n"
    else:
        assert result.stdout == expected


@pytest.mark.parametrize("errors,expected", [("replace", "�"), ("backslashreplace", "\\xff")])
def test_requested_decode_error_policy_is_applied_to_retained_bytes(runner, errors, expected):
    result = runner.execute("import os\nos.write(1,b'\\xff')", cap=32, text=True,
                            encoding="utf-8", errors=errors)
    assert result.stdout == expected


def test_untruncated_invalid_text_still_raises_and_reaps(runner):
    with pytest.raises(UnicodeDecodeError):
        runner.execute("import os\nos.write(1,b'\\xff')", text=True, encoding="utf-8")
    assert runner.records[0][0].returncode == 0
    assert all(s.closed for s in runner.streams)


def test_discarded_bytes_are_not_decoded_after_explicit_truncation(runner):
    result = runner.execute("import os\nos.write(1,b'ok'+b'\\xff'*1000)", cap=2, text=True)
    assert result.stdout == "ok\n[sandbox: stdout capture truncated at 2 bytes]\n"


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_under_and_exact_cap_output_has_no_loss_marker(runner, text):
    result = runner.execute("import os\nos.write(1,b'a'*97);os.write(2,b'b'*96)", text=text)
    assert result.stdout == ("a" * 97 if text else b"a" * 97)
    assert result.stderr == ("b" * 96 if text else b"b" * 96)


def test_merged_stderr_is_one_bounded_stream(runner):
    result = runner.execute("import os\nos.write(1,b'o'*1000);os.write(2,b'e'*1000)", cap=1010,
                            capture_output=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert result.stdout == b"o" * 1000 + b"e" * 10 + b"\n[sandbox: stdout capture truncated at 1010 bytes]\n"
    assert result.stderr is None


def test_redirected_files_are_neither_read_nor_closed(runner):
    with (runner.out / "redirected").open("wb+") as output:
        result = runner.execute("import os\nos.write(1,b'x'*1000)", cap=1,
                                capture_output=False, stdout=output, stderr=subprocess.PIPE)
        assert result.stdout is None and result.stderr == b""
        assert not output.closed
        output.seek(0)
        assert output.read() == b"x" * 1000


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_empty_input_delivers_eof(runner, text):
    result = runner.execute("import sys\nassert sys.stdin.buffer.read()==b''", input="" if text else b"", text=text)
    assert result.returncode == 0 and result.stdout == ("" if text else b"")


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_early_stdin_close_does_not_break_output_drain(runner, text):
    result = runner.execute("import os\nos.close(0)\nos.write(1,b'done')", input="x" * 1048576 if text else b"x" * 1048576, text=text)
    assert result.returncode == 0 and result.stdout == ("done" if text else b"done")


@pytest.mark.parametrize("cap", [-1, 0, 4])
def test_zero_and_negative_caps_still_drain_to_completion(runner, cap):
    result = runner.execute("import os\nos.write(1,b'x'*1000)", cap=cap)
    normalized = max(0, cap)
    assert result.stdout == b"x" * normalized + f"\n[sandbox: stdout capture truncated at {normalized} bytes]\n".encode()
    assert result.returncode == 0


@pytest.mark.parametrize("cap,kind", [(float("nan"), ValueError), (float("inf"), OverflowError), ("invalid", ValueError)])
def test_invalid_capture_limits_refuse_before_creating_a_process(runner, cap, kind):
    with pytest.raises(kind):
        runner.execute("pass", cap=cap)
    assert runner.records == []


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_uncapped_calls_keep_the_existing_communicate_path(runner, text):
    runner.forbid_communicate = False
    result = runner.execute("import os\nos.write(1,b'x'*1000)", cap=None, text=text)
    assert result.stdout == ("x" * 1000 if text else b"x" * 1000)
    assert runner.communicators == []


@pytest.mark.parametrize("cap,value", [(3, "éé"), (1, "🦕"), (0, "value"), (3, b"abcdef")])
def test_final_result_clamping_is_idempotent_without_duplicate_markers(cap, value):
    result = subprocess.CompletedProcess(["owned"], 0, value, None)
    ctx._apply_capture_ceiling(result, cap)
    first = result.stdout
    ctx._apply_capture_ceiling(result, cap)
    assert result.stdout == first


def test_snapshot_metadata_cannot_bypass_the_result_size_bound():
    result = subprocess.CompletedProcess(["owned"], 0, b"x" * 10000, None)
    result._capture_limit_snapshot = (1, result.stdout, None)
    ctx._apply_capture_ceiling(result, 1)
    assert result.stdout == b"x\n[sandbox: stdout capture truncated at 1 bytes]\n"


def test_payload_that_looks_like_a_marker_is_still_treated_as_payload(runner):
    payload = b"\n[sandbox: stdout capture truncated at 1 bytes]\n"
    result = runner.execute(f"import os\nos.write(1,{payload!r})", cap=1)
    assert result.stdout == payload[:1] + payload


@requires_landlock
@pytest.mark.parametrize("cap,text", [(0, False), (97, False), (3, True)])
def test_real_landlock_fallback_uses_the_bounded_owner(runner, monkeypatch, cap, text):
    if sys.platform != "linux":
        pytest.skip("real Linux Landlock-only executor")
    monkeypatch.setattr(ctx, "check_net_available", lambda: False)
    monkeypatch.setattr(ctx, "check_mount_available", lambda: False)
    result = runner.execute(FLOOD, cap=cap, text=text, native=True)
    assert result.returncode == 0 and len(runner.communicators) == 1
    assert runner.communicators[0].peak <= 2 * cap


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, OSError])
def test_failure_after_read_keeps_the_same_bounded_owner_during_cleanup(runner, monkeypatch, kind):
    primary = kind("owned capture interruption")
    original = ctx.BoundedCommunicator._accept
    interrupted = []
    def accept(owner, label, chunk):
        original(owner, label, chunk)
        if not interrupted and label == "stdout":
            interrupted.append(owner)
            raise primary
    monkeypatch.setattr(ctx.BoundedCommunicator, "_accept", accept)
    with pytest.raises(kind) as raised:
        runner.execute(FLOOD)
    assert raised.value is primary
    assert runner.unbounded_calls == 0
    assert runner.communicators == interrupted
    assert runner.communicators[0].outputs()[0].startswith(b"o" * 97)
    assert runner.communicators[0].peak <= 194
    assert runner.records[0][0].returncode is not None
    assert all(stream.closed for stream in runner.streams)


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
@pytest.mark.parametrize("native", [False, pytest.param(True, marks=requires_landlock)],
                         ids=["plain", "landlock"])
def test_real_timeout_keeps_bounded_raw_snapshots_and_reaps(runner, monkeypatch, text, native):
    if native:
        if sys.platform != "linux":
            pytest.skip("real Linux Landlock-only executor")
        monkeypatch.setattr(ctx, "check_net_available", lambda: False)
        monkeypatch.setattr(ctx, "check_mount_available", lambda: False)
    ready_r, ready_w = os.pipe()
    runner.descriptors.extend([ready_r, ready_w])
    park_r, park_w = os.pipe()
    runner.descriptors.extend([park_r, park_w])
    def wait_ready(proc):
        poller = select.poll()
        poller.register(ready_r, select.POLLIN)
        assert poller.poll(5000), "owned output writer did not become ready"
        assert os.read(ready_r, 1) == b"R"
    runner.configure = wait_ready
    program = ("import os\n"
               "os.write(1,b'p\\r\\n'*100);os.write(2,b'e\\r\\n'*100)\n"
               f"os.write({ready_w},b'R')\n"
               f"os.read({park_r},1)\n")
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        runner.execute(program, text=text, timeout=0.05, pass_fds=(ready_w, park_r), native=native)
    error = raised.value
    assert error.timeout == 0.05
    assert error.output == (b"p\r\n" * 100)[:97] + b"\n[sandbox: stdout capture truncated at 97 bytes]\n"
    assert error.stderr == (b"e\r\n" * 100)[:97] + b"\n[sandbox: stderr capture truncated at 97 bytes]\n"
    status = runner.records[0][0].returncode
    assert status not in (None, -9) if native else status == -9
    assert runner.unbounded_calls == 0 and len(runner.communicators) == 1
    assert runner.communicators[0].peak <= 194


def test_oversized_descriptor_capture_uses_poll_and_closes_its_owned_copy(runner):
    original_limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        soft, hard = original_limits
        if soft != resource.RLIM_INFINITY and soft <= 1100:
            desired = 2048 if hard == resource.RLIM_INFINITY else min(2048, hard)
            if desired <= 1100:
                pytest.skip("hard descriptor limit is too low for the owned high-fd probe")
            resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
        high_fds = []
        def duplicate(proc):
            high = fcntl.fcntl(proc.stdout.fileno(), fcntl.F_DUPFD_CLOEXEC, 1100)
            try:
                stream = os.fdopen(high, "rb", buffering=0)
            except BaseException:
                os.close(high)
                raise
            runner.streams.append(stream)
            proc.stdout = stream
            high_fds.append(high)
        runner.configure = duplicate
        result = runner.execute("import os\nos.write(1,b'high descriptor')")
        assert result.stdout == b"high descriptor" and high_fds[0] >= 1100
        assert runner.records[0][0].stdout.closed
        assert runner.unbounded_calls == 0
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, original_limits)


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_nonzero_check_failure_contains_the_bounded_output(runner, text):
    with pytest.raises(subprocess.CalledProcessError) as raised:
        runner.execute("import os,sys\nos.write(1,b'x'*1000);sys.exit(7)", text=text, check=True)
    expected = b"x" * 97 + b"\n[sandbox: stdout capture truncated at 97 bytes]\n"
    assert raised.value.returncode == 7
    assert raised.value.output == (expected.decode() if text else expected)
    assert runner.records[0][0].returncode == 7


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_invalid_input_type_still_finishes_the_started_process(runner, text):
    with pytest.raises(AttributeError if text else TypeError):
        runner.execute("import sys\nsys.stdin.buffer.read()", input=b"data" if text else "data", text=text)
    assert runner.records[0][0].returncode is not None
    assert all(stream.closed for stream in runner.streams)
    assert runner.unbounded_calls == 0


def test_large_integral_limit_does_not_format_an_unused_loss_marker(runner):
    result = runner.execute("import os\nos.write(1,b'small')", cap=10 ** 5000)
    assert result.stdout == b"small" and result.returncode == 0


@requires_landlock
def test_native_runtime_grants_keep_unrelated_owned_files_unreadable(runner, monkeypatch, tmp_path):
    """Runtime discovery must feed read grants without removing confinement."""
    if sys.platform != "linux":
        pytest.skip("real Linux Landlock-only executor")
    monkeypatch.setattr(ctx, "check_net_available", lambda: False)
    monkeypatch.setattr(ctx, "check_mount_available", lambda: False)
    # A sibling of target=tmp_path, never inside its existing read grant.
    with TemporaryDirectory(prefix="runtime-witness-", dir=tmp_path.parent) as outside:
        runtime = Path(outside) / "runtime"
        runtime.mkdir()
        declared = runtime / "owned-runtime-data"
        private = Path(outside) / "unrelated-private-data"
        declared.write_text("runtime-ok")
        private.write_text("host-readable")
        assert private.read_text() == "host-readable"
        paths = python_runtime_tool_paths() + [str(runtime)]
        monkeypatch.setitem(globals(), "python_runtime_tool_paths", lambda: paths)
        program = (
            "import errno\n"
            f"assert open({str(declared)!r}).read() == 'runtime-ok'\n"
            f"try: open({str(private)!r}).read()\n"
            "except PermissionError as exc: assert exc.errno == errno.EACCES\n"
            "else: raise AssertionError('read confinement was removed')\n"
            "print('runtime-ok; unrelated read denied')\n"
        )
        result = runner.execute(program, native=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout == b"runtime-ok; unrelated read denied\n"
