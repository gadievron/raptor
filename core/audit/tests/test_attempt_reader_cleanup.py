"""Attempt recovery retains scan failures when its owned reader closes."""
import io
from types import SimpleNamespace

import pytest

from core.audit import attempt_reservations as consumer
from core.audit import record
from core.json.utils import save_json
from core.run.report_identity import fresh_identity
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private"))
    save_json(run / ".raptor-run.json", {
        "command": "audit", "status": "running",
        "reporting_identity": fresh_identity(),
    })
    initial = consumer.AttemptReservations(run, resume=False)
    assert initial.gap is None
    paths = record.audit_log_paths(run)
    originals = {path: path.read_bytes() for path in paths}
    assert originals and all(originals.values())
    state = SimpleNamespace(primary=None, cleanup=None, readers=[], native=[],
                            lines=[], closes=0, initial=initial)
    native_fdopen = consumer.os.fdopen

    class Reader(io.BufferedReader):
        def readline(self, size=-1):
            data = super().readline(size)
            state.lines.append(data)
            if state.primary is not None:
                raise state.primary
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    def fdopen(fd, mode):
        assert mode == "rb"
        native = native_fdopen(fd, mode)
        state.native.append(native)
        reader = Reader(native)
        state.readers.append(reader)
        return reader

    patch_module_attribute(monkeypatch, consumer, "os", "fdopen", fdopen)
    state.run = lambda: consumer.AttemptReservations(run, resume=True)
    try:
        yield state
    finally:
        for reader in state.readers:
            if not reader.closed:
                io.BufferedReader.close(reader)
        assert {path: path.read_bytes() for path in paths} == originals


def assert_retired(state):
    assert state.lines and all(line.endswith(b"\n") for line in state.lines)
    assert state.closes == len(state.readers) == len(state.native) == 1
    assert all(reader.closed for reader in state.readers + state.native)


@pytest.mark.parametrize("primary", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup", [OSError, MemoryError])
def test_scan_cancellation_survives_consumed_close(recovery, primary, cleanup):
    recovery.primary = primary("after native journal line read")
    recovery.cleanup = cleanup("after native journal close")
    with pytest.raises(primary) as caught:
        recovery.run()
    assert caught.value is recovery.primary
    assert_retired(recovery)


def test_scan_refusal_retains_specific_gap(recovery):
    recovery.primary = ValueError("truncated_attempt_recovery_trail")
    recovery.cleanup = OSError("after native journal close")
    assert recovery.run().gap == "truncated_attempt_recovery_trail"
    assert_retired(recovery)


@pytest.mark.parametrize("cleanup", [OSError, KeyboardInterrupt])
def test_fresh_close_failure_retains_existing_policy(recovery, cleanup):
    recovery.cleanup = cleanup("after native journal close")
    if cleanup is OSError:
        assert recovery.run().gap == "unreadable_attempt_recovery_state"
    else:
        with pytest.raises(cleanup) as caught:
            recovery.run()
        assert caught.value is recovery.cleanup
    assert_retired(recovery)


def test_healthy_signed_recovery_keeps_identity(recovery):
    restored = recovery.run()
    assert restored.gap is None
    assert restored.identity == recovery.initial.identity
    assert restored.pending() == []
    assert restored.known_spend_usd == recovery.initial.known_spend_usd
    assert_retired(recovery)
