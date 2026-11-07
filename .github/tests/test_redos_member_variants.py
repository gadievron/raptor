"""Every distinct member variant must earn its pin and nightly verdict."""

import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from core.testing.module_views import module_function_view


@pytest.fixture(scope="module")
def census():
    path = Path(__file__).with_name("test_redos_idiom_census.py")
    spec = importlib.util.spec_from_file_location("owned_redos_variants", path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(module)
    return module


def _consumer(census, tmp_path, scan, verdict, measurements, lanes=None):
    key = ("owned.py", "PATTERNS")
    members = {key: {"digests": {"a", "b"}, "rules": {"C"}, "sites": [
        (1, "first", 0, "search"), (2, "first", 0, "search"),
        (3, "second", 2, "search"),
    ]}}
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"members": {"\x1f".join(key): {
        "digests": ["a", "b"], "rules": ["C"], "verdict": verdict, "exp": 1.0,
    }}}))
    calls = []

    def classify(pattern, flags, *mode):
        calls.append((pattern, flags, mode))
        return measurements[pattern]

    cls = census.ScanRestartNightly if scan else census.TrailingSpanNightly
    consumer = module_function_view(census, bindings={
        "_SCAN_EXPECTED_FILE" if scan else "_EXPECTED_FILE": path,
        "_scan_restart_members" if scan else "_trailing_span_members": lambda: members,
        "_scan_oracle_classify" if scan else "_oracle_classify": classify,
        "_site_scan_lanes": lambda site: (lanes or {}).get(site.pattern, []),
        "_owned_nightly": cls.test_nightly_oracle_agrees_with_pins,
    })
    return consumer, path, calls, cls


def _regenerate(consumer, scan):
    fn = consumer._regen_scan_expected if scan else consumer._regen_expected
    return fn(workers=1)


@pytest.mark.parametrize("scan", [False, True], ids=["trailing", "scan"])
@pytest.mark.parametrize("unsupported", [False, True], ids=["superlinear", "mixed-disposition"])
def test_regeneration_refuses_unacceptable_second_variant(census, tmp_path, scan, unsupported):
    second = (None, False) if unsupported else (2.0, True)
    consumer, path, calls, _ = _consumer(census, tmp_path, scan, "linear", {
        "first": (1.0, True), "second": second,
    })
    before = path.read_bytes()
    assert _regenerate(consumer, scan) == 1
    assert path.read_bytes() == before
    assert [call[0] for call in calls] == ["first", "second"]


@pytest.mark.parametrize("scan", [False, True], ids=["trailing", "scan"])
@pytest.mark.parametrize("supported", [False, True], ids=["noattack", "linear"])
def test_regeneration_combines_consistent_variants_once(census, tmp_path, scan, supported):
    measurements = ({"first": (0.8, True), "second": (1.2, True)} if supported else
                    {"first": (None, False), "second": (None, False)})
    consumer, path, calls, _ = _consumer(census, tmp_path, scan, "linear", measurements)
    assert _regenerate(consumer, scan) == 0
    row = json.loads(path.read_text())["members"]["owned.py\x1fPATTERNS"]
    assert row["digests"] == ["a", "b"]
    assert row["exp"] == (1.2 if supported else None)
    assert row["verdict"] == ("linear" if supported else "noattack")
    assert [call[0] for call in calls] == ["first", "second"]


@pytest.mark.parametrize("scan", [False, True], ids=["trailing", "scan"])
@pytest.mark.parametrize("verdict", ["linear", "noattack"])
def test_nightly_checks_second_variant(census, tmp_path, scan, verdict):
    measurements = {"first": (1.0, True) if verdict == "linear" else (None, False),
                    "second": (2.0, True) if verdict == "linear" else (1.0, True)}
    consumer, _, calls, cls = _consumer(census, tmp_path, scan, verdict, measurements)
    with pytest.raises(AssertionError, match="line 3"):
        consumer._owned_nightly(cls())
    assert sorted(call[0] for call in calls) == ["first", "second"]


@pytest.mark.parametrize("scan", [False, True], ids=["trailing", "scan"])
def test_adjudicated_variants_do_not_start_ignored_measurements(census, tmp_path, scan):
    consumer, _, calls, cls = _consumer(census, tmp_path, scan, "adjudicated", {})
    consumer._owned_nightly(cls())
    assert calls == []


@pytest.mark.parametrize("nightly", [False, True], ids=["regeneration", "nightly"])
def test_scan_cap_applies_to_second_variant(census, tmp_path, nightly):
    consumer, path, _, cls = _consumer(census, tmp_path, True, "linear", {
        "first": (1.0, True), "second": (1.0, True),
    }, {"second": [{}] * (census._SCAN_LANE_CAP + 1)})
    before = path.read_bytes()
    if nightly:
        with pytest.raises(AssertionError, match="line 3.*over the classify cap"):
            consumer._owned_nightly(cls())
    else:
        assert _regenerate(consumer, True) == 1
        assert path.read_bytes() == before


def test_starved_first_variant_does_not_hide_measurable_second(census, tmp_path):
    consumer, _, calls, cls = _consumer(census, tmp_path, True, "noattack", {
        "first": (1.0, True), "second": (1.0, True),
    }, {"first": [{"starved": True}], "second": [{}]})
    with pytest.raises(AssertionError, match="line 3"):
        consumer._owned_nightly(cls())
    assert len(calls) == 2


def test_scan_regeneration_refuses_mixed_starvation(census, tmp_path):
    consumer, path, _, _ = _consumer(census, tmp_path, True, "linear", {
        "first": (1.0, True), "second": (1.0, True),
    }, {"second": [{"starved": True}]})
    before = path.read_bytes()
    assert _regenerate(consumer, True) == 1
    assert path.read_bytes() == before


def test_variant_identity_includes_flags_and_mode_and_is_local_to_member(census):
    sites = [(1, "literal", 0, "search"), (2, "literal", 0, "search"),
             (3, "literal", 2, "search"), (4, "literal", 0, "match")]
    members = {("b.py", "B"): {"sites": sites}, ("a.py", "A"): {"sites": sites}}
    variants = list(census._member_variants(members))
    assert [(key, site[0]) for key, _, site in variants] == [
        ((path, name), line) for path, name in [("a.py", "A"), ("b.py", "B")]
        for line in [1, 3, 4]
    ]
    assert all(record is members[key] for key, record, _ in variants)
