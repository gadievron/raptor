"""Profile unions preserve order without repeated full-list searches."""

import pytest

from core.sandbox.observe_profile import ConnectTarget, ObserveProfile

FIELDS = ("paths_read", "paths_written", "paths_stat", "connect_targets")


def value(field, number):
    if field == "connect_targets":
        return ConnectTarget(f"2001:db8::{number:x}", 443, "AF_INET6")
    return f"/path/{number}"


@pytest.mark.parametrize("field", FIELDS)
def test_merge_preserves_existing_duplicates_and_first_seen_order(field):
    original = [value(field, i) for i in (1, 1, 0)]
    incoming = [value(field, i) for i in (2, 1, 3, 2)]
    left = ObserveProfile(**{field: list(original)})
    right = ObserveProfile(**{field: list(incoming)})
    left.merge(right)
    assert getattr(left, field) == original + [value(field, 2), value(field, 3)]
    assert getattr(right, field) == incoming


@pytest.mark.parametrize("field", FIELDS)
def test_membership_work_grows_linearly(field):
    comparisons = []

    class CountedPath(str):
        __hash__ = str.__hash__

        def __eq__(self, other):
            comparisons.append(True)
            return super().__eq__(other)

    class CountedTarget(ConnectTarget):
        __hash__ = ConnectTarget.__hash__

        def __eq__(self, other):
            comparisons.append(True)
            return super().__eq__(other)

    def item(i):
        if field == "connect_targets":
            return CountedTarget(f"2001:db8::{i:x}", 443, "AF_INET6")
        return CountedPath(f"/path/{i}")

    size = 500
    left = ObserveProfile(**{field: [item(i) for i in range(size)]})
    right = ObserveProfile(**{field: [item(i) for i in range(size // 2, size + size // 2)]})
    left.merge(right)
    # Count equality operations rather than elapsed time: a quadratic
    # regression fails deterministically even on a fast or busy runner.
    assert len(comparisons) < 20 * size
    assert len(getattr(left, field)) == size + size // 2


def test_metadata_still_accumulates_and_trust_never_increases():
    left = ObserveProfile(
        paths_read=["/first"], dropped_by_category={"read": 2},
    )
    right = ObserveProfile(
        paths_read=["/first", "/second"],
        budget_truncated=True, dropped_by_category={"read": 3, "network": 1},
        nonce_trusted=False,
    )
    left.merge(right)
    left.merge(ObserveProfile(paths_read=["/third"]))
    assert left.paths_read == ["/first", "/second", "/third"]
    assert left.dropped_by_category == {"read": 5, "network": 1}
    assert left.budget_truncated is True
    assert left.nonce_trusted is False


def test_empty_merge_does_not_scan_existing_observations():
    hashes = []

    class CountedPath(str):
        def __hash__(self):
            hashes.append(True)
            return super().__hash__()

    path = CountedPath("/existing")
    left = ObserveProfile(paths_read=[path])
    left.merge(ObserveProfile())
    assert hashes == []
    assert left.paths_read == ["/existing"]


def test_caller_edits_are_respected_by_later_merges():
    left = ObserveProfile(paths_read=["/first"])
    left.merge(ObserveProfile(paths_read=["/second"]))
    left.paths_read.remove("/first")
    left.paths_read.append("/manual")
    left.merge(ObserveProfile(paths_read=["/manual", "/first", "/last"]))
    assert left.paths_read == ["/second", "/manual", "/first", "/last"]
