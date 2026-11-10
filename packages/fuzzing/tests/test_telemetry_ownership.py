"""Native telemetry file lifetime, without a fuzzer or target process."""
import pytest

from packages.fuzzing.telemetry import FuzzingTelemetry


def test_stop_cancellation_closes_native_event_writer(tmp_path):
    primary = KeyboardInterrupt("campaign-end callback cancelled")

    def event_callback(event):
        if event.kind == "campaign_end":
            raise primary

    telemetry = FuzzingTelemetry(tmp_path, fuzzer="inert", on_event=event_callback)
    telemetry.start()
    stream = telemetry._events_fp
    assert stream is not None
    try:
        with pytest.raises(KeyboardInterrupt) as raised:
            telemetry.stop()
        assert raised.value is primary
        assert stream.closed
        assert telemetry._events_fp is None
        assert not telemetry.summary_path.exists()
    finally:
        stream.close()
        telemetry._events_fp = None


@pytest.fixture
def telemetry_io(tmp_path, monkeypatch):
    state = {"stage": None, "primary": None, "cleanup": None, "closes": 0}

    def callback(event):
        if event.kind == "campaign_end" and state["stage"] == "callback":
            raise state["primary"]

    telemetry = FuzzingTelemetry(tmp_path, fuzzer="inert", on_event=callback)
    telemetry.start()
    native = telemetry._events_fp
    assert native is not None
    finish = telemetry._reporter.finish

    def report(stats):
        finish(stats)
        if state["stage"] == "reporter":
            raise state["primary"]

    class Stream:
        def __getattr__(self, name):
            return getattr(native, name)

        def close(self):
            native.close()
            state["closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    telemetry._events_fp = Stream()
    monkeypatch.setattr(telemetry._reporter, "finish", report)
    state.update(telemetry=telemetry, native=native)
    try:
        yield state
    finally:
        native.close()
        telemetry._events_fp = None


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_callback_cancellation_survives_consumed_close(telemetry_io, primary_type, close_type):
    primary = primary_type("end callback cancelled")
    telemetry_io.update(stage="callback", primary=primary,
                        cleanup=close_type("after native writer close"))
    telemetry = telemetry_io["telemetry"]
    with pytest.raises(primary_type) as raised:
        telemetry.stop()
    assert raised.value is primary
    assert telemetry_io["native"].closed
    assert telemetry_io["closes"] == 1
    assert telemetry._events_fp is None
    assert not telemetry.summary_path.exists()


@pytest.mark.parametrize("primary_type", [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_reporter_failure_retires_writer(telemetry_io, primary_type, close_type):
    primary = primary_type("after actual finish rendering")
    telemetry_io.update(stage="reporter", primary=primary,
                        cleanup=close_type("after native writer close") if close_type else None)
    telemetry = telemetry_io["telemetry"]
    with pytest.raises(primary_type) as raised:
        telemetry.stop()
    assert raised.value is primary
    assert telemetry_io["native"].closed
    assert telemetry_io["closes"] == 1
    assert telemetry._events_fp is None
    assert not telemetry.summary_path.exists()


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_writer_close_failure_remains_visible(telemetry_io, close_type):
    cleanup = close_type("after native writer close")
    telemetry_io["cleanup"] = cleanup
    telemetry = telemetry_io["telemetry"]
    with pytest.raises(close_type) as raised:
        telemetry.stop()
    assert raised.value is cleanup
    assert telemetry_io["native"].closed
    assert telemetry_io["closes"] == 1
    assert telemetry._events_fp is None
    assert not telemetry.summary_path.exists()


def test_successful_stop_closes_writer_and_publishes_summary(telemetry_io):
    telemetry = telemetry_io["telemetry"]
    telemetry.stop()
    assert telemetry_io["native"].closed
    assert telemetry_io["closes"] == 1
    assert telemetry._events_fp is None
    assert telemetry.summary_path.is_file()


def test_ordinary_callback_error_remains_ignored(telemetry_io):
    telemetry_io.update(stage="callback", primary=ValueError("optional callback failed"))
    telemetry = telemetry_io["telemetry"]
    telemetry.stop()
    assert telemetry_io["native"].closed
    assert telemetry_io["closes"] == 1
    assert telemetry._events_fp is None
    assert telemetry.summary_path.is_file()
