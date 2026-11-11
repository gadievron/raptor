"""Batch journal flush retains operation errors and native stream ownership."""
import errno
import os
from types import SimpleNamespace

import pytest

from core import source
from core.audit import collector
from core.coverage import journal
from core.coverage.tests.test_journal_append import _entry
from core.testing.module_views import module_function_view, scoped_function_imports


@pytest.fixture
def flush_probe(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    run = tmp_path / "run"
    journal.append_entry(run, _entry(1))
    path = run / journal.JOURNAL_FILENAME
    state = {"run": run, "path": path, "before": path.read_bytes(), "owned": [],
             "events": [], "primary": None, "cleanup": None, "open_calls": []}

    class OwnedStream:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()

        def __enter__(self):
            assert self.stream.__enter__() is self.stream
            state["events"].append("enter")
            return self

        def __exit__(self, *args):
            self.stream.__exit__(*args)
            state["events"].append("close")
            if state["cleanup"] is not None:
                raise state["cleanup"]

        def fileno(self):
            return self.fd

    def open_regular(*args, **kwargs):
        state["open_calls"].append((args, kwargs))
        stream = source.open_regular(*args, **kwargs)
        if stream is None:
            return None
        wrapper = OwnedStream(stream)
        state["owned"].append(wrapper)
        return wrapper

    def fsync(fd):
        os.fsync(fd)
        state["events"].append("fsync")
        if state["primary"] is not None:
            raise state["primary"]

    view = module_function_view(journal, bindings={
        "os": SimpleNamespace(**{**vars(os), "fsync": fsync}),
    })
    with scoped_function_imports(view, ("flush_journal",), {"core.source": source}) as imports:
        getattr(imports, "core.source").open_regular = open_regular
        state["flush"] = view.flush_journal
        try:
            yield state
        finally:
            for wrapper in state["owned"]:
                if not wrapper.stream.closed:
                    wrapper.stream.close()


def assert_closed_unchanged(state):
    assert state["events"] == ["enter", "fsync", "close"]
    assert len(state["owned"]) == len(state["open_calls"]) == 1
    wrapper = state["owned"][0]
    assert wrapper.stream.closed
    with pytest.raises(OSError) as retired:
        os.fstat(wrapper.fd)
    assert retired.value.errno == errno.EBADF
    assert state["path"].read_bytes() == state["before"]


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("close_fails", [False, True])
@pytest.mark.parametrize("primary_type", [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_flush_primary_survives_close(flush_probe, strict, close_fails, primary_type):
    primary = primary_type("owned fsync after-effect failure")
    flush_probe["primary"] = primary
    if close_fails:
        flush_probe["cleanup"] = OSError("owned stream-close after-effect failure")
    with pytest.raises(primary_type) as raised:
        flush_probe["flush"](flush_probe["run"], strict=strict)
    assert raised.value is primary
    assert_closed_unchanged(flush_probe)


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_flush_close_failure_remains_visible(flush_probe, strict, cleanup_type):
    failure = cleanup_type("owned stream-close after-effect failure")
    flush_probe["cleanup"] = failure
    with pytest.raises(cleanup_type) as raised:
        flush_probe["flush"](flush_probe["run"], strict=strict)
    assert raised.value is failure
    assert_closed_unchanged(flush_probe)


@pytest.mark.parametrize("strict", [False, True])
def test_native_batch_flush_preserves_journal(flush_probe, strict):
    assert flush_probe["flush"](flush_probe["run"], strict=strict) is None
    assert_closed_unchanged(flush_probe)


def test_optional_missing_flush_still_skips(flush_probe, tmp_path):
    assert flush_probe["flush"](tmp_path / "missing") is None
    assert flush_probe["open_calls"]
    assert not flush_probe["owned"] and not flush_probe["events"]


def test_collector_flush_does_not_swallow_cancellation(flush_probe, tmp_path, monkeypatch):
    primary = KeyboardInterrupt("owned flush cancellation")
    flush_probe["primary"] = primary
    flush_probe["cleanup"] = OSError("owned stream-close after-effect failure")
    monkeypatch.setattr(collector, "flush_journal", flush_probe["flush"])
    owner = collector.Collector(flush_probe["run"], tmp_path)
    with pytest.raises(KeyboardInterrupt) as raised:
        owner.flush()
    assert raised.value is primary
    assert_closed_unchanged(flush_probe)
