"""Scalar caller temporary-file teardown; compiler callbacks never execute."""
import tempfile
import subprocess
from types import SimpleNamespace

import pytest

from core.audit import preprocessor_view
from core.detectors import scalar_aliasing as consumer
from core.detectors.budget import WorkBudget
from core.sandbox import SandboxSetupError


@pytest.fixture
def scalar_io(tmp_path, monkeypatch):
    target = tmp_path / "owned-input"
    target.mkdir()
    source = "int plain;\n"
    (target / "a.c").write_text(source)
    view = preprocessor_view.ExpandedView(
        ok=True, file_path="a.c", text=source,
        line_map=(("a.c", 1), None), source_files=("a.c",))
    monkeypatch.setattr(preprocessor_view, "expand_translation_unit", lambda **_kw: view)
    state = {"streams": [], "closes": [], "primary": None, "cleanup": {}, "calls": 0}

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

    def temporary(*args, **kwargs):
        stream = Stream(tempfile.TemporaryFile(*args, **kwargs), len(state["streams"]) + 1)
        state["streams"].append(stream)
        return stream

    def runner(_command, **kwargs):
        state["calls"] += 1
        if state["primary"] is not None:
            raise state["primary"]
        kwargs["stdout"].write(b'{"kind":"TranslationUnitDecl","inner":[]}')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(consumer, "tempfile", SimpleNamespace(
        **{**vars(tempfile), "TemporaryFile": temporary}))
    state["run"] = lambda: consumer.corroborate_aliasing(
        target, "a.c", [{"file": "a.c", "line": 1}],
        gcc="not-executed-gcc", clang="not-executed-clang", sandbox_run=runner,
        budget=WorkBudget(10), scratch_root=str(tmp_path / "owned-scratch"))
    try:
        yield state
    finally:
        for stream in state["streams"]:
            stream.native.close()


def test_refusal_survives_native_capture_file_cleanup(scalar_io):
    primary = SandboxSetupError("injected compiler refusal; no execution")
    scalar_io["primary"] = primary
    scalar_io["cleanup"] = {1: OSError("after native stdout close"),
                            2: OSError("after native stderr close")}
    with pytest.raises(SandboxSetupError) as raised:
        scalar_io["run"]()
    assert raised.value is primary
    assert scalar_io["calls"] == 1
    assert scalar_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in scalar_io["streams"])


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_unexpected_primary_survives_both_stream_closes(scalar_io, primary_type, close_type):
    primary = primary_type("injected compiler interruption")
    scalar_io["primary"] = primary
    scalar_io["cleanup"] = {1: close_type("after native stdout close"),
                            2: close_type("after native stderr close")}
    with pytest.raises(primary_type) as raised:
        scalar_io["run"]()
    assert raised.value is primary
    assert scalar_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in scalar_io["streams"])


def test_refusal_survives_close_cancellation(scalar_io):
    primary = SandboxSetupError("injected compiler refusal")
    scalar_io["primary"] = primary
    scalar_io["cleanup"] = {1: KeyboardInterrupt("after native stdout close"),
                            2: KeyboardInterrupt("after native stderr close")}
    with pytest.raises(SandboxSetupError) as raised:
        scalar_io["run"]()
    assert raised.value is primary
    assert scalar_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in scalar_io["streams"])


@pytest.mark.parametrize("kind", ["io", "value", "timeout", "memory", "unsupported"])
@pytest.mark.parametrize("close_io", [False, True])
def test_ordinary_failure_retains_incomplete_result(scalar_io, kind, close_io):
    primary = {"io": OSError("injected IO"), "value": ValueError("injected value"),
               "timeout": subprocess.TimeoutExpired(["not-executed"], 1),
               "memory": MemoryError("injected allocation"),
               "unsupported": consumer._Unsupported("explicit unsupported input")}[kind]
    scalar_io["primary"] = primary
    if close_io:
        scalar_io["cleanup"] = {1: OSError("after native stdout close")}
    result = scalar_io["run"]()
    detail = ("OSError" if close_io else "explicit unsupported input" if kind == "unsupported"
              else type(primary).__name__)
    assert not result.complete
    assert result.proofs == []
    assert result.limitations == ["scalar aliasing corroboration unavailable: " + detail]
    assert scalar_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in scalar_io["streams"])


@pytest.mark.parametrize("primary_type", [OSError, ValueError])
@pytest.mark.parametrize("stream_index", [1, 2])
def test_cancellation_after_handled_failure_stays_fresh(scalar_io, primary_type, stream_index):
    scalar_io["primary"] = primary_type("injected ordinary failure")
    cleanup = KeyboardInterrupt("after native stream close")
    scalar_io["cleanup"] = {stream_index: cleanup}
    with pytest.raises(KeyboardInterrupt) as raised:
        scalar_io["run"]()
    assert raised.value is cleanup
    assert scalar_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in scalar_io["streams"])


@pytest.mark.parametrize("stream_index", [1, 2])
def test_fresh_close_io_retains_incomplete_result(scalar_io, stream_index):
    scalar_io["cleanup"] = {stream_index: OSError("after native stream close")}
    result = scalar_io["run"]()
    assert not result.complete
    assert not result.proofs
    assert result.limitations == ["scalar aliasing corroboration unavailable: OSError"]
    assert scalar_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in scalar_io["streams"])


def test_fresh_close_cancellation_stays_visible(scalar_io):
    cleanup = KeyboardInterrupt("after native stdout close")
    scalar_io["cleanup"] = {1: cleanup}
    with pytest.raises(KeyboardInterrupt) as raised:
        scalar_io["run"]()
    assert raised.value is cleanup
    assert scalar_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in scalar_io["streams"])


def test_successful_empty_capture_control_closes_both_files(scalar_io):
    result = scalar_io["run"]()
    assert result.complete
    assert result.proofs == []
    assert result.limitations == []
    assert scalar_io["calls"] == 1
    assert scalar_io["closes"] == [2, 1]
    assert all(stream.native.closed for stream in scalar_io["streams"])
