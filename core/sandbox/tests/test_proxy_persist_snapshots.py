"""Proxy persistence snapshots must not share mutable parent state."""

import threading

import pytest

from core.sandbox import summary


@pytest.fixture(autouse=True)
def isolated_mirror(monkeypatch):
    monkeypatch.setattr(summary, "_proxy_persist_state", {})


def test_snapshot_is_stable_after_later_parent_updates(tmp_path):
    summary.record_proxy_persist_state(tmp_path, expected_count=2, flags=["first"])
    snapshot = summary.get_proxy_persist_state(tmp_path)
    summary.record_proxy_persist_state(tmp_path, expected_count=5, flags=["second"])
    assert snapshot == {"expected_count": 2, "flags": ["first"]}
    assert summary.get_proxy_persist_state(tmp_path) == {
        "expected_count": 5, "flags": ["first", "second"],
    }


def test_caller_cannot_clear_or_inject_parent_flags(tmp_path):
    summary.record_proxy_persist_state(tmp_path, expected_count=2, flags=["original"])
    snapshot = summary.get_proxy_persist_state(tmp_path)
    snapshot["flags"].clear()
    snapshot["flags"].append("injected")
    snapshot["expected_count"] = -1
    assert summary.get_proxy_persist_state(tmp_path) == {
        "expected_count": 2, "flags": ["original"],
    }


def test_separate_readers_receive_independent_flag_lists(tmp_path):
    summary.record_proxy_persist_state(tmp_path, expected_count=1, flags=["first"])
    first = summary.get_proxy_persist_state(tmp_path)
    second = summary.get_proxy_persist_state(tmp_path)
    assert first == second
    assert first["flags"] is not second["flags"]
    first["flags"].append("reader-local")
    assert second["flags"] == ["first"]


def test_count_stays_monotonic_and_flags_stay_ordered_and_unique(tmp_path):
    flags = ["first"]
    summary.record_proxy_persist_state(tmp_path, expected_count=3, flags=flags)
    flags.append("caller-local")
    summary.record_proxy_persist_state(tmp_path, expected_count=1, flags=["first", "second"])
    assert summary.get_proxy_persist_state(tmp_path) == {
        "expected_count": 3, "flags": ["first", "second"],
    }


def test_snapshot_history_keeps_each_counts_matching_flags(tmp_path):
    snapshots = []
    for number in range(1, 4):
        summary.record_proxy_persist_state(
            tmp_path, expected_count=number, flags=[f"revision-{number}"],
        )
        snapshots.append(summary.get_proxy_persist_state(tmp_path))
    for number, snapshot in enumerate(snapshots, 1):
        assert snapshot["expected_count"] == number
        assert snapshot["flags"] == [f"revision-{i}" for i in range(1, number + 1)]


def test_snapshot_survives_an_update_from_another_thread(tmp_path):
    summary.record_proxy_persist_state(tmp_path, expected_count=1, flags=["first"])
    release = threading.Event()
    errors = []

    def update():
        try:
            assert release.wait(5)
            summary.record_proxy_persist_state(tmp_path, expected_count=2, flags=["second"])
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=update, daemon=True)
    thread.start()
    try:
        snapshot = summary.get_proxy_persist_state(tmp_path)
        release.set()
        thread.join(5)
        assert not thread.is_alive()
        assert not errors
        assert snapshot == {"expected_count": 1, "flags": ["first"]}
        assert summary.get_proxy_persist_state(tmp_path)["expected_count"] == 2
    finally:
        release.set()
        thread.join(5)


def test_missing_run_has_no_snapshot(tmp_path):
    assert summary.get_proxy_persist_state(tmp_path) is None
