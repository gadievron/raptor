"""Reuse structural work without losing sites or carrying state across scans."""

import hashlib
import importlib.util
from pathlib import Path
import re
import sys
from unittest.mock import patch

import pytest

from core.testing.module_views import module_function_view


@pytest.fixture(scope="module")
def census():
    path = Path(__file__).with_name("test_redos_idiom_census.py")
    spec = importlib.util.spec_from_file_location("owned_scan_membership_reuse", path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(module)
    return module


def _reference(census, sites):
    """The uncached aggregation, including table identities and site order."""
    members = {}
    for site in sites:
        if not census._site_scan_lanes(site):
            continue
        digest = hashlib.sha256(
            f"{site.flags}:{site.mode}:{site.pattern}".encode(),
        ).hexdigest()[:12]
        key = site.key
        if site.origin == "table":
            key = (site.key[0], f"{site.name.rsplit('[', 1)[0]}[sha256:{digest}]")
        row = members.setdefault(key, {"digests": set(), "sites": []})
        row["digests"].add(digest)
        row["sites"].append((site.lineno, site.pattern, site.flags, site.mode))
    return members


def test_distinct_structure_once_preserves_all_records(census):
    site = census._Site
    pattern = r"\b\w+\s*\("
    sites = [
        site(("first.py", "call"), 1, pattern, 0, "search", None),
        site(("second.py", "call"), 2, pattern, 0, "search", None),
        site(("first.py", "call"), 3, pattern, 0, "search", None),
        site(("first.py", "call"), 4, pattern, re.IGNORECASE, "search", None),
        site(("first.py", "call"), 5, pattern, int(re.IGNORECASE), "search", None),
        site(("first.py", "match"), 6, pattern, 0, "match", None),
        site(("first.py", "fullmatch"), 7, pattern, 0, "fullmatch", None),
        site(("table.py", "rows"), 8, pattern, 0, "search", "rows[0]", "table"),
        site(("table.py", "rows"), 9, pattern, 0, "search", "rows[4]", "table"),
        site(("other.py", "rows"), 10, pattern, 0, "search", "rows[0]", "table"),
        site(("literal.py", "one"), 11, "literal", 0, "search", None),
        site(("literal.py", "two"), 12, "literal", 0, "search", None),
        site(("invalid.py", "one"), 13, "[", 0, "search", None),
        site(("invalid.py", "two"), 14, "[", 0, "search", None),
    ]
    calls = []

    def classify(item):
        calls.append((item.pattern, item.flags, item.mode))
        return census._site_scan_lanes(item)

    consumer = module_function_view(census, bindings={
        "_all_runtime_sites": lambda: sites, "_site_scan_lanes": classify,
    })
    actual = consumer._scan_restart_members()
    assert actual == _reference(census, sites)
    assert len(actual) == 4
    assert len(actual[("first.py", "call")]["sites"]) == 4
    assert len(actual[("first.py", "call")]["digests"]) == 3
    assert len(calls) == len(set(calls)) == 6


def test_each_invocation_reclassifies_and_owns_its_records(census):
    site = census._Site(("owned.py", "call"), 1, r"\b\w+\s*\(", 0, "search", None)
    decision = [True]
    calls = []

    def classify(item):
        calls.append(item)
        return [{"owned": True}] if decision[0] else []

    consumer = module_function_view(census, bindings={
        "_all_runtime_sites": lambda: [site, site], "_site_scan_lanes": classify,
    })
    first = consumer._scan_restart_members()
    second = consumer._scan_restart_members()
    assert first == second and first is not second
    first[site.key]["sites"].clear()
    first[site.key]["digests"].clear()
    assert len(second[site.key]["sites"]) == 2
    assert len(second[site.key]["digests"]) == 1
    decision[0] = False
    assert consumer._scan_restart_members() == {}
    assert calls == [site, site, site]
