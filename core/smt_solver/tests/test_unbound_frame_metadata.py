"""An unbound assertion frame cannot manufacture captured proof metadata."""

import pytest

from core.smt_solver import assertion_frames as frames


@pytest.fixture(autouse=True)
def absent_backend_and_no_query(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("unbound metadata reader entered a solver query")
    monkeypatch.setattr(frames, "z3", None)
    monkeypatch.setattr(frames, "Z3_ERRORS", ())
    monkeypatch.setattr(frames, "check_solver", forbidden)


def test_default_frame_has_no_core_or_origin_without_backend():
    frame = frames.TrackedFrames()
    assert frame.core_indices(None) is None
    assert frame.single_core_origin(None) is None
    assert frame._core is None


def test_unbound_check_refuses_before_any_query():
    frame = frames.TrackedFrames()
    with pytest.raises(ValueError, match="tracked frame assertions changed"):
        frame.check()
    assert frame._core is None


def test_wrong_solver_identity_has_no_captured_proof():
    frame = frames.TrackedFrames()
    assert frame.core_indices(object()) is None
    assert frame.single_core_origin(object()) is None


def test_same_object_without_assertion_interface_has_no_proof():
    supplied = object()
    frame = frames.TrackedFrames(_solver=supplied)
    assert frame.core_indices(supplied) is None
    assert frame.single_core_origin(supplied) is None
    with pytest.raises(ValueError, match="tracked frame assertions changed"):
        frame.check()


def test_caller_maps_remain_snapshotted_even_when_backend_is_absent():
    labels, origins = {"marker": "condition"}, {"marker": 0}
    frame = frames.TrackedFrames(labels, origins)
    labels["marker"], origins["marker"] = "changed", 1
    assert frame.labels["marker"] == "condition"
    assert frame.origins["marker"] == 0
    assert frame.single_core_origin(None) is None
