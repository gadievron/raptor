"""Telemetry startup owns its native writer until initialization returns."""
import os
from types import SimpleNamespace

import pytest

from packages.fuzzing import telemetry as consumer
from packages.fuzzing.telemetry import FuzzingTelemetry


def test_start_cancellation_retires_native_writer(tmp_path):
    primary = KeyboardInterrupt("start callback cancelled")
    writers = []

    def callback(event):
        if event.kind == "campaign_start":
            writers.append(telemetry._events_fp)
            raise primary

    telemetry = FuzzingTelemetry(tmp_path, fuzzer="inert", on_event=callback)
    try:
        with pytest.raises(KeyboardInterrupt) as raised:
            telemetry.start()
        assert raised.value is primary
        assert len(writers) == 1
        assert writers[0] is not None and writers[0].closed
        assert telemetry._events_fp is None
    finally:
        for stream in writers:
            if stream is not None:
                stream.close()
        if telemetry._events_fp is not None:
            telemetry._events_fp.close()
            telemetry._events_fp = None


@pytest.fixture
def startup_io(tmp_path, monkeypatch):
    state = {"stage": None, "primary": None, "cleanup": None, "closes": 0,
             "native": None}
    native_info = consumer.logger.info
    native_debug = consumer.logger.debug

    def callback(event):
        if event.kind == "campaign_start" and state["stage"] == "callback":
            raise state["primary"]

    def info(*args, **kwargs):
        native_info(*args, **kwargs)
        if state["stage"] == "logger":
            raise state["primary"]

    class Stream:
        def __getattr__(self, name):
            return getattr(state["native"], name)

        def close(self):
            state["native"].close()
            state["closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    def fdopen(*args, **kwargs):
        native = os.fdopen(*args, **kwargs)
        assert state["native"] is None
        state["native"] = native
        return Stream()

    monkeypatch.setattr(consumer, "os", SimpleNamespace(**{**vars(os), "fdopen": fdopen}))
    monkeypatch.setattr(consumer, "logger", SimpleNamespace(info=info, debug=native_debug))
    state["telemetry"] = FuzzingTelemetry(tmp_path, fuzzer="inert", on_event=callback)
    try:
        yield state
    finally:
        if state["native"] is not None:
            state["native"].close()
        state["telemetry"]._events_fp = None


@pytest.mark.parametrize(("primary_type", "close_type"), [
    (KeyboardInterrupt, OSError), (KeyboardInterrupt, KeyboardInterrupt),
    (SystemExit, None), (SystemExit, OSError), (SystemExit, KeyboardInterrupt),
])
def test_start_callback_failure_closes_installed_writer(startup_io, primary_type, close_type):
    primary = primary_type("start callback cancelled")
    startup_io.update(stage="callback", primary=primary,
                      cleanup=close_type("after native close") if close_type else None)
    telemetry = startup_io["telemetry"]
    with pytest.raises(primary_type) as raised:
        telemetry.start()
    assert raised.value is primary
    assert startup_io["native"].closed
    assert startup_io["closes"] == 1
    assert telemetry._events_fp is None
    assert not telemetry.summary_path.exists()


@pytest.mark.parametrize("primary_type", [OSError, RuntimeError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_start_diagnostic_failure_keeps_primary_and_retires_writer(
        startup_io, primary_type, close_type):
    primary = primary_type("after actual startup log")
    startup_io.update(stage="logger", primary=primary,
                      cleanup=close_type("after native close") if close_type else None)
    telemetry = startup_io["telemetry"]
    with pytest.raises(primary_type) as raised:
        telemetry.start()
    assert raised.value is primary
    assert startup_io["native"].closed
    assert startup_io["closes"] == 1
    assert telemetry._events_fp is None
    assert not telemetry.summary_path.exists()


def test_success_keeps_writer_until_normal_stop(startup_io):
    telemetry = startup_io["telemetry"]
    telemetry.start()
    assert not startup_io["native"].closed
    assert telemetry._events_fp is not None
    assert startup_io["closes"] == 0
    telemetry.stop()
    assert startup_io["native"].closed
    assert startup_io["closes"] == 1
    assert telemetry._events_fp is None
    assert telemetry.summary_path.is_file()


def test_start_optional_callback_error_stays_ignored(startup_io):
    startup_io.update(stage="callback", primary=ValueError("optional callback failed"))
    telemetry = startup_io["telemetry"]
    telemetry.start()
    assert not startup_io["native"].closed
    assert telemetry._events_fp is not None
    telemetry.stop()
    assert startup_io["native"].closed
    assert startup_io["closes"] == 1
    assert telemetry.summary_path.is_file()
