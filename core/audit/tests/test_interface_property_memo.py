"""Shared body-property scans keep mutable route facts isolated."""

from dataclasses import asdict

import pytest

from core.audit import consistency_dimensions as dim
from core.audit import sibling_analysis as sibling
from core.audit.sibling_analysis import SiblingGroup, SiblingPath
from core.audit.uniform_absence import uniform_absence_records
from core.testing import requires_ts


def fixture():
    names = [f"handle_{i}" for i in range(4)]
    sources = {"app.py": "\n".join(f"def {name}(req):\n    return load(req)\n" for name in names)}
    groups = [SiblingGroup(group_id=f"route:{index}", sibling_type="route_family",
                          description="route family", siblings=[
        SiblingPath(label=name, file="app.py", function=name,
                    properties={dim._ROUTE_AUTH_PRESENCE_PROPERTY: i != index})
        for i, name in enumerate(names)]) for index in (0, 3)]
    return sources, groups


@requires_ts("python")
def test_cross_consumer_reuse_keeps_route_votes_and_absence(monkeypatch):
    sources, groups = fixture()
    expected = dim.detect_interface_deviations(sources, groups)
    expected_absence = uniform_absence_records(sources, groups)
    assert {d.enclosing_function for d in expected} == {"handle_0", "handle_3"}
    assert expected_absence
    original = sibling._AUTH_CHECK_RE
    calls = []

    class Counted:
        def search(self, body):
            calls.append(body)
            return original.search(body)

    monkeypatch.setattr(sibling, "_AUTH_CHECK_RE", Counted())
    memo = dim.InterfacePropertyMemo()
    actual = dim.detect_interface_deviations(sources, groups, _property_memo=memo)
    absence = uniform_absence_records(sources, groups, _property_memo=memo)
    assert [asdict(d) for d in actual] == [asdict(d) for d in expected]
    assert absence == expected_absence
    assert len(calls) == 4  # Four unique bodies, sixteen member votes.
    assert all(dim._ROUTE_AUTH_PRESENCE_PROPERTY not in p for p in memo.properties.values())


def test_returned_dicts_are_isolated():
    memo = dim.InterfacePropertyMemo()
    body = "return load(req)"
    expected = dim.interface_properties(body)
    first = dim.interface_properties(body, _memo=memo)
    first["auth_check"] = not expected["auth_check"]
    first["route_auth_decorator_present"] = True
    second = dim.interface_properties(body, _memo=memo)
    assert second == expected
    second.clear()
    assert dim.interface_properties(body, _memo=memo) == expected


@pytest.mark.parametrize("limit,value", [
    ("_INTERFACE_PROPERTY_MAX_ENTRIES", 1), ("_INTERFACE_PROPERTY_MAX_CHARS", 3),
])
def test_retention_limits_do_not_limit_scans(monkeypatch, limit, value):
    monkeypatch.setattr(dim, limit, value)
    memo = dim.InterfacePropertyMemo()
    for body in ("abc", "different", "abc", "different"):
        assert dim.interface_properties(body, _memo=memo) == dim.interface_properties(body)
    assert list(memo.properties) == ["abc"]
    assert memo.retained_chars == 3


def test_failed_scan_is_retried(monkeypatch):
    original = sibling._AUTH_CHECK_RE
    calls = []

    class Flaky:
        def search(self, body):
            calls.append(body)
            if len(calls) == 1:
                raise ValueError("transient failure")
            return original.search(body)

    monkeypatch.setattr(sibling, "_AUTH_CHECK_RE", Flaky())
    memo = dim.InterfacePropertyMemo()
    with pytest.raises(ValueError):
        dim.interface_properties("body", _memo=memo)
    assert memo.properties == {} and memo.retained_chars == 0
    assert dim.interface_properties("body", _memo=memo)["auth_check"] is False
    assert len(calls) == 2


@requires_ts("python")
def test_prepass_matches_uncached_results(monkeypatch):
    from core.audit.consistency_prepass import run_consistency_prepass

    sources, groups = fixture()
    cached = run_consistency_prepass(sources, peer_groups=groups, budget_s=360)
    original = dim._interface_properties
    def uncached(body, **kw):
        return original(body)
    monkeypatch.setattr(dim, "_interface_properties", uncached)
    monkeypatch.setattr(dim, "interface_properties", uncached)
    baseline = run_consistency_prepass(sources, peer_groups=groups, budget_s=360)
    cached["telemetry"].pop("wall_time_s")
    baseline["telemetry"].pop("wall_time_s")
    assert cached == baseline
