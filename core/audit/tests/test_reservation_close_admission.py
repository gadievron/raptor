"""Runtime close cannot be followed by installation of a newly reserved owner."""
import pytest

from core.audit.tests.test_knowledge_runtime_coordinator import _runtime


@pytest.mark.parametrize("phase", ["healthy", "before", "admission_true", "admission_false",
                                   "admission_error", "after_reserve", "installed"])
def test_close_boundary_preserves_runtime_reservation_ownership(tmp_path, monkeypatch, phase):
    runtime, ctx = _runtime(tmp_path)
    key = runtime._gap_key({"file": ctx["file"], "name": ctx["function"], "line_start": 1})
    cycle = runtime._cycles[key]
    original = cycle.reserve
    admitted = []
    primary = KeyboardInterrupt("owned admission close interruption")

    def admit():
        admitted.append(True)
        if phase.startswith("admission"):
            runtime.close("owned_admission_close")
        if phase == "admission_error":
            raise primary
        return phase != "admission_false"

    def reserve_then_close(*args, **kwargs):
        packet = original(*args, **kwargs)
        assert packet is not None
        assert cycle.state_record()["active_pass_id"] == packet.pass_id
        runtime.close("owned_after_reserve_close")
        return packet

    try:
        if phase == "before":
            runtime.close("owned_before_reserve_close")
        with monkeypatch.context() as patch:
            if phase == "after_reserve":
                patch.setattr(cycle, "reserve", reserve_then_close)
            if phase == "admission_error":
                with pytest.raises(KeyboardInterrupt) as caught:
                    runtime.ready_continuations(admission=admit)
                assert caught.value is primary
                reservations = ()
            else:
                reservations = runtime.ready_continuations(admission=admit)
        assert len(admitted) == (0 if phase == "before" else 1)
        assert cycle.started == (0 if phase in {"before", "admission_false", "admission_error"} else 1)
        assert runtime._calls.get(key, 0) == 0
        if phase in {"healthy", "installed"}:
            reservation, = reservations
            assert runtime._active_units[key] is reservation
            if phase == "installed":
                runtime.close("owned_after_install_close")
            else:
                assert not runtime._closed
                assert runtime.fail(reservation, "owned_cleanup")
        else:
            assert not reservations
        assert not runtime._active and not runtime._active_units and not runtime._reserving
        assert cycle.state_record()["active_pass_id"] is None
        if phase != "healthy":
            assert runtime._closed and not runtime.client_lifetime_valid()
        if phase in {"admission_true", "after_reserve"}:
            assert any(event.event == "continuation_failed" and event.reason == "runtime_closed"
                       for event in cycle.events())
            assert not any(event["event"] == "continuation_reserved" for event in runtime.events())
        before = runtime.events()
        runtime.close("owned_final_close")
        if phase != "healthy":
            assert runtime.events() == before
        assert not runtime.ready_continuations(admission=lambda: True)
    finally:
        runtime.close("test_complete")
