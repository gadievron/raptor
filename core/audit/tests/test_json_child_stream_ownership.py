"""Caller stream teardown only: native files and a non-executing runner seam."""
import tempfile
import subprocess
from types import SimpleNamespace

import pytest

from core.audit import subproc_json as consumer
from core.binary import _inspection_policy
from core.config import RaptorConfig
from core.sandbox import SandboxSetupError, python_paths
from core.security import env_sanitisation


@pytest.fixture
def child_io(tmp_path, monkeypatch):
    state = {"streams": [], "closes": [], "primary": None, "cleanup": {},
             "calls": 0, "reads": []}

    class Stream:
        def __init__(self, native, index):
            self.native, self.index = native, index

        def __getattr__(self, name):
            return getattr(self.native, name)

        def __enter__(self):
            self.native.__enter__()
            return self

        def __exit__(self, *exc):
            self.native.__exit__(*exc)
            state["closes"].append(self.index)
            if self.index in state["cleanup"]:
                raise state["cleanup"][self.index]

        def read(self, size):
            state["reads"].append((self.index, size))
            return self.native.read(size)

    def temporary(*args, **kwargs):
        wrapped = Stream(tempfile.TemporaryFile(*args, **kwargs), len(state["streams"]) + 1)
        state["streams"].append(wrapped)
        return wrapped

    def runner(*_args, **kwargs):
        state["calls"] += 1
        if state["primary"] is not None:
            raise state["primary"]
        kwargs["stdout"].write(b'{"ok":true}')
        kwargs["stderr"].write(b'inert diagnostic')
        return SimpleNamespace(returncode=0)

    # Explicit caller-only seams: no real profile resolution, HOME/provider
    # reads, subprocess or native confinement is exercised or claimed.
    monkeypatch.setattr(_inspection_policy, "inspection_options", lambda *_args: {"tool_paths": []})
    monkeypatch.setattr(python_paths, "python_runtime_tool_paths", lambda: [])
    monkeypatch.setattr(python_paths, "_home_roots", lambda: ())
    monkeypatch.setattr(RaptorConfig, "get_safe_env", staticmethod(lambda: {}))
    monkeypatch.setattr(env_sanitisation, "subprocess_tmpdir", lambda: str(tmp_path))
    monkeypatch.setattr(consumer, "site", SimpleNamespace(getusersitepackages=lambda: ""))
    monkeypatch.setattr(consumer, "tempfile", SimpleNamespace(
        **{**vars(tempfile), "TemporaryFile": temporary}))
    monkeypatch.setattr(consumer, "_sandbox_run", runner)
    state["run"] = lambda: consumer.run_json_child(
        "core.audit.sweep:_run_smt_verb_inner_json", {}, env={}, timeout=1)
    try:
        yield state
    finally:
        for stream in state["streams"]:
            stream.native.close()


def test_refusal_is_not_converted_to_optional_io_miss(child_io):
    primary = SandboxSetupError("injected runner refusal; no child executed")
    child_io["primary"] = primary
    child_io["cleanup"] = {2: OSError("after native stderr close"),
                           1: OSError("after native stdout close")}
    with pytest.raises(SandboxSetupError) as raised:
        child_io["run"]()
    assert raised.value is primary
    assert child_io["calls"] == 1
    assert child_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in child_io["streams"])


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit, MemoryError])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_primary_survives_both_stream_teardowns(child_io, primary_type, close_type):
    primary = primary_type("injected runner interruption")
    child_io["primary"] = primary
    child_io["cleanup"] = {1: close_type("after native stdout close"),
                           2: close_type("after native stderr close")}
    with pytest.raises(primary_type) as raised:
        child_io["run"]()
    assert raised.value is primary
    assert child_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in child_io["streams"])


def test_refusal_survives_cleanup_interruption(child_io):
    primary = SandboxSetupError("injected refusal; no execution")
    child_io["primary"] = primary
    child_io["cleanup"] = {1: KeyboardInterrupt("after native stdout close"),
                           2: KeyboardInterrupt("after native stderr close")}
    with pytest.raises(SandboxSetupError) as raised:
        child_io["run"]()
    assert raised.value is primary
    assert child_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in child_io["streams"])


@pytest.mark.parametrize("kind", ["io", "timeout"])
@pytest.mark.parametrize("stream_index", [1, 2])
def test_close_cancellation_after_handled_io_remains_fresh(child_io, kind, stream_index):
    child_io["primary"] = (OSError("injected IO") if kind == "io" else
                           subprocess.TimeoutExpired(["not-executed"], 1))
    cleanup = KeyboardInterrupt("after native stream close")
    child_io["cleanup"] = {stream_index: cleanup}
    with pytest.raises(KeyboardInterrupt) as raised:
        child_io["run"]()
    assert raised.value is cleanup
    assert child_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in child_io["streams"])


@pytest.mark.parametrize("kind", ["io", "timeout"])
@pytest.mark.parametrize("close_failure", [False, True])
def test_handled_runner_failure_remains_none(child_io, kind, close_failure):
    child_io["primary"] = (OSError("injected IO") if kind == "io" else
                           subprocess.TimeoutExpired(["not-executed"], 1))
    if close_failure:
        child_io["cleanup"] = {1: OSError("after native stdout close"),
                               2: OSError("after native stderr close")}
    assert child_io["run"]() is None
    assert child_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in child_io["streams"])


def test_success_decodes_only_capped_native_output(child_io):
    assert child_io["run"]() == {"ok": True}
    assert child_io["calls"] == 1
    assert child_io["reads"] == [(1, consumer.MAX_REPLY_BYTES + 1), (2, 2048)]
    assert child_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in child_io["streams"])


def test_fresh_close_io_failure_remains_optional(child_io):
    child_io["cleanup"] = {1: OSError("after native stdout close")}
    assert child_io["run"]() is None
    assert child_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in child_io["streams"])


def test_fresh_close_cancellation_remains_visible(child_io):
    cleanup = KeyboardInterrupt("after native stdout close")
    child_io["cleanup"] = {1: cleanup}
    with pytest.raises(KeyboardInterrupt) as raised:
        child_io["run"]()
    assert raised.value is cleanup
    assert child_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in child_io["streams"])
