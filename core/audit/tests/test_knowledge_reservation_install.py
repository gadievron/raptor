"""Interrupted cycle reservation cannot strand an unregistered active pass."""
import pytest

from core.audit.tests.test_knowledge_runtime_coordinator import _runtime


@pytest.mark.parametrize("interrupt", [False, True], ids=["healthy", "interrupted"])
def test_cycle_reservation_retains_owner_until_install_or_retirement(tmp_path, monkeypatch, interrupt):
    runtime, ctx = _runtime(tmp_path)
    key = runtime._gap_key({"file": ctx["file"], "name": ctx["function"], "line_start": 1})
    cycle = runtime._cycles[key]
    original = cycle.reserve
    packets = []

    def reserve_then_interrupt(*args, **kwargs):
        packet = original(*args, **kwargs)
        assert packet is not None
        packets.append(packet)
        assert cycle.state_record()["active_pass_id"] == packet.pass_id
        if interrupt:
            raise KeyboardInterrupt("owned interruption after actual reservation")
        return packet

    try:
        with monkeypatch.context() as patch:
            patch.setattr(cycle, "reserve", reserve_then_interrupt)
            if interrupt:
                with pytest.raises(KeyboardInterrupt, match="after actual reservation"):
                    runtime.ready_continuations(admission=lambda: True)
            else:
                reservation, = runtime.ready_continuations(admission=lambda: True)
                assert reservation.packet is packets[0]
                assert runtime._active_units[key] is reservation
                assert runtime.fail(reservation, "owned_cleanup")
        assert len(packets) == cycle.started == 1
        assert runtime._calls.get(key, 0) == 0
        assert not runtime._reserving and not runtime._active and not runtime._active_units
        runtime.close("owned_close")
        assert cycle.state_record()["active_pass_id"] is None
        assert not runtime.ready_continuations(admission=lambda: True)
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("phase", ["before", "partial", "snapshot", "cleanup"])
def test_reservation_install_failure_keeps_primary_error_and_owned_cleanup(tmp_path, monkeypatch, phase):
    runtime, ctx = _runtime(tmp_path)
    key = runtime._gap_key({"file": ctx["file"], "name": ctx["function"], "line_start": 1})
    cycle = runtime._cycles[key]
    original_reserve, original_failed = cycle.reserve, cycle.failed
    primary = KeyboardInterrupt("owned install interruption")

    def reserve_error(*args, **kwargs):
        if phase == "cleanup":
            assert original_reserve(*args, **kwargs) is not None
        raise primary

    class InterruptedInstall(dict):
        def __setitem__(self, item, value):
            super().__setitem__(item, value)
            raise primary

    def snapshot_error():
        raise primary

    def cleanup_error(*args, **kwargs):
        raise OSError("owned cleanup refusal")

    try:
        with monkeypatch.context() as patch:
            if phase in {"before", "cleanup"}:
                patch.setattr(cycle, "reserve", reserve_error)
            elif phase == "partial":
                patch.setattr(runtime, "_active_units", InterruptedInstall())
            else:
                patch.setattr(cycle, "state_record", snapshot_error)
            if phase == "cleanup":
                patch.setattr(cycle, "failed", cleanup_error)
            with pytest.raises(KeyboardInterrupt) as caught:
                runtime.ready_continuations(admission=lambda: True)
            assert caught.value is primary
            assert not runtime._reserving and not runtime._active and not runtime._active_units
        assert cycle.started == (1 if phase in {"partial", "cleanup"} else 0)
        assert runtime._calls.get(key, 0) == 0
        if phase == "cleanup":
            assert cycle.state_record()["active_pass_id"] is not None
            assert primary.__notes__ == ["Reservation cleanup also failed: OSError"]
        else:
            assert cycle.state_record()["active_pass_id"] is None
    finally:
        active = cycle.state_record()["active_pass_id"]
        if active is not None:
            original_failed(active, reason="owned_test_cleanup")
        runtime.close("test_complete")


def test_reservation_exception_preserves_preexisting_cycle_owner(tmp_path, monkeypatch):
    from time import monotonic
    from core.audit.refutation_source import capture_source_identity

    runtime, ctx = _runtime(tmp_path)
    key = runtime._gap_key({"file": ctx["file"], "name": ctx["function"], "line_start": 1})
    cycle = runtime._cycles[key]
    packet = cycle.reserve(now=monotonic(), current_source=capture_source_identity(tmp_path, ctx["file"]),
        admission=lambda: True, all_model_calls=0)
    assert packet is not None

    def interrupted_reserve(*args, **kwargs):
        raise KeyboardInterrupt("owned before-reserve interruption")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(cycle, "reserve", interrupted_reserve)
            with pytest.raises(KeyboardInterrupt, match="before-reserve"):
                runtime.ready_continuations(admission=lambda: True)
        assert cycle.state_record()["active_pass_id"] == packet.pass_id
        assert cycle.started == 1
        assert not runtime._active and not runtime._active_units and not runtime._reserving
    finally:
        cycle.failed(packet.pass_id, reason="owned_test_cleanup")
        runtime.close("test_complete")


def test_no_new_packet_leaves_consumed_round_and_runtime_maps_unchanged(tmp_path):
    runtime, _ctx = _runtime(tmp_path)
    try:
        reservation, = runtime.ready_continuations(admission=lambda: True)
        assert runtime.fail(reservation, "owned_completed_attempt")
        before = runtime.events()
        assert not runtime.ready_continuations(admission=lambda: True)
        assert runtime.events() == before
        assert runtime._cycles[runtime._key(reservation.origin)].started == 1
        assert not runtime._active and not runtime._active_units and not runtime._reserving
    finally:
        runtime.close("test_complete")
