"""Scratch fixture scopes restore borrowed objects after joining owned tickers."""

import pytest

from core.run import scratch
from core.testing.scratch_state import isolated_scratch_keepalive


@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt, SystemExit], ids=["success", "error", "interrupt", "exit"])
def test_scope_restores_inherited_state(tmp_path, error):
    names = ("_keepalive_paths", "_keepalive_thread", "_keepalive_loop")
    before = {name: getattr(scratch, name) for name in names}
    inherited_paths = set(before["_keepalive_paths"])
    thread = None

    def exercise():
        nonlocal thread
        with isolated_scratch_keepalive() as paths:
            with scratch.scratch_dir("raptor-state-test-", dir=tmp_path, keepalive=True) as root:
                thread = scratch._keepalive_thread
                assert thread.is_alive() and str(root) in paths
                if error:
                    raise error("test body failure")

    if error:
        with pytest.raises(error, match="test body failure"):
            exercise()
    else:
        exercise()
    assert thread is not None and not thread.is_alive()
    assert before["_keepalive_paths"] == inherited_paths
    assert all(getattr(scratch, name) is original for name, original in before.items())


def test_nested_scope_preserves_outer_registration(tmp_path):
    with isolated_scratch_keepalive() as outer:
        with scratch.scratch_dir("raptor-state-test-", dir=tmp_path, keepalive=True) as root:
            outer_thread = scratch._keepalive_thread
            with isolated_scratch_keepalive() as inner:
                assert not inner and inner is not outer
                with scratch.scratch_dir("raptor-state-test-", dir=tmp_path, keepalive=True):
                    inner_thread = scratch._keepalive_thread
                    assert inner_thread is not outer_thread
            assert not inner_thread.is_alive()
            assert scratch._keepalive_thread is outer_thread
            assert scratch._keepalive_paths is outer and str(root) in outer


def test_scope_reports_pin_leak_and_still_joins_and_restores(tmp_path):
    original = scratch._keepalive_paths
    original_thread = scratch._keepalive_thread
    with pytest.raises(AssertionError, match="left scratch keepalives registered"):
        with isolated_scratch_keepalive():
            scratch.keepalive_register(tmp_path)
            owned_thread = scratch._keepalive_thread
    assert not owned_thread.is_alive()
    assert scratch._keepalive_paths is original
    assert scratch._keepalive_thread is original_thread
