"""Tests for ``packages.sca.api_compat`` — heuristic risk signals
for X → Y dependency upgrades."""

from __future__ import annotations

from typing import Optional

from packages.sca.api_compat import (
    UpgradeCompatReport,
    UpgradeCompatRisk,
    check_pypi_api_compat,
)


# ---------------------------------------------------------------------------
# semver-bump heuristic — pure version-string analysis, no network
# ---------------------------------------------------------------------------


def test_minor_bump_no_risk():
    report = check_pypi_api_compat("requests", "2.30.0", "2.31.0")
    assert report.risks == []
    assert report.overall_severity == "info"


def test_patch_bump_no_risk():
    report = check_pypi_api_compat("requests", "2.31.0", "2.31.1")
    assert report.risks == []


def test_major_bump_high_severity():
    report = check_pypi_api_compat("django", "3.2.0", "4.0.0")
    assert len(report.risks) == 1
    assert report.risks[0].kind == "semver_major"
    assert report.risks[0].severity == "high"
    assert "semver-major" in report.risks[0].detail
    assert report.overall_severity == "high"


def test_zero_to_one_is_medium_not_high():
    """Pre-1.0 packages don't follow semver guarantees, so a 0.x → 1.x
    bump shouldn't be flagged as ``high`` — but it IS still worth
    surfacing because the 1.0 release frequently locks in API changes."""
    report = check_pypi_api_compat("foo", "0.5.0", "1.0.0")
    assert len(report.risks) == 1
    assert report.risks[0].kind == "semver_major"
    assert report.risks[0].severity == "medium"
    assert "1.0 stability boundary" in report.risks[0].detail


def test_downgrade_flagged():
    """Operators rarely intend a major-version downgrade."""
    report = check_pypi_api_compat("django", "4.0.0", "3.2.0")
    assert len(report.risks) == 1
    assert report.risks[0].severity == "high"
    assert "DOWNGRADE" in report.risks[0].detail


def test_unparseable_version_no_semver_signal():
    """When the version string isn't semver-shaped (e.g. PEP 440
    epoch / local version), we silently skip the semver heuristic
    rather than emitting a confused risk row."""
    # PEP 440 local-version suffix ("+local") still has a parseable
    # ``major.minor.patch`` prefix, so the heuristic correctly
    # reports semver_major across that prefix. This asserts the
    # positive case so we notice if the leading-prefix regex
    # regresses.
    report = check_pypi_api_compat("foo", "1.0.0+local", "2.0.0+local")
    assert any(r.kind == "semver_major" for r in report.risks)
    # Genuinely unparseable shape — no risk row at all.
    report2 = check_pypi_api_compat("foo", "weird-tag", "another-weird-tag")
    assert report2.risks == []


def test_v_prefix_handled():
    """Some ecosystems / projects tag versions ``v1.0.0`` rather than
    ``1.0.0``. The heuristic should be robust to either."""
    report = check_pypi_api_compat("foo", "v1.0.0", "v2.0.0")
    assert len(report.risks) == 1
    assert report.risks[0].kind == "semver_major"


# ---------------------------------------------------------------------------
# Dep-set comparison — requires_dist diff via stub HTTP
# ---------------------------------------------------------------------------


class _StubHttp:
    """In-memory PyPI-shaped stub for dep-set tests."""

    def __init__(self, payloads):
        self._payloads = payloads
        self.calls = []

    def get_json(self, url: str, headers: Optional[dict] = None):
        self.calls.append(url)
        for fragment, payload in self._payloads.items():
            if fragment in url:
                return payload
        raise RuntimeError(f"unexpected URL: {url}")


def test_dep_set_added_signal():
    http = _StubHttp({
        "/2.30.0/json": {"info": {"requires_dist": [
            "charset-normalizer<4,>=2",
            "idna<4,>=2.5",
        ]}},
        "/2.31.0/json": {"info": {"requires_dist": [
            "charset-normalizer<4,>=2",
            "idna<4,>=2.5",
            "urllib3>=1.21.1",     # NEW
            "certifi>=2017.4.17",  # NEW
        ]}},
    })
    report = check_pypi_api_compat("requests", "2.30.0", "2.31.0", http=http)
    kinds = [r.kind for r in report.risks]
    assert "deps_added" in kinds
    added = next(r for r in report.risks if r.kind == "deps_added")
    assert "2 new" in added.detail
    assert "certifi" in added.detail and "urllib3" in added.detail


def test_dep_set_removed_signal():
    http = _StubHttp({
        "/1.0.0/json": {"info": {"requires_dist": [
            "six>=1.10",
            "requests>=2.20",
        ]}},
        "/2.0.0/json": {"info": {"requires_dist": [
            "requests>=2.20",
        ]}},
    })
    report = check_pypi_api_compat("foo", "1.0.0", "2.0.0", http=http)
    kinds = [r.kind for r in report.risks]
    assert "deps_removed" in kinds
    # Major bump also fires.
    assert "semver_major" in kinds


def test_dep_set_unchanged_no_risk():
    same_deps = {"info": {"requires_dist": ["six>=1.10"]}}
    http = _StubHttp({
        "/2.30.0/json": same_deps,
        "/2.31.0/json": same_deps,
    })
    report = check_pypi_api_compat("foo", "2.30.0", "2.31.0", http=http)
    # Same minor bump + identical dep sets = clean.
    assert report.risks == []


def test_dep_name_canonicalised():
    """``Django`` and ``django`` should be considered the same dep
    (PEP 503 canonicalisation)."""
    http = _StubHttp({
        "/1.0/json": {"info": {"requires_dist": ["Django>=3.2"]}},
        "/1.1/json": {"info": {"requires_dist": ["django>=3.2"]}},
    })
    report = check_pypi_api_compat("foo", "1.0", "1.1", http=http)
    assert all(r.kind != "deps_added" for r in report.risks)
    assert all(r.kind != "deps_removed" for r in report.risks)


def test_pep503_separator_canonicalisation():
    """``my_pkg``, ``my-pkg``, ``my.pkg`` are the same dep."""
    http = _StubHttp({
        "/1.0/json": {"info": {"requires_dist": ["my_pkg>=1.0"]}},
        "/1.1/json": {"info": {"requires_dist": ["my-pkg>=1.0"]}},
    })
    report = check_pypi_api_compat("foo", "1.0", "1.1", http=http)
    assert not any(r.kind in ("deps_added", "deps_removed")
                   for r in report.risks)


def test_dep_added_summary_caps_at_5():
    """Long added-dep lists shouldn't fill the report — cap at 5 +
    "(+N more)" suffix."""
    new_deps = ["pkg" + str(i) for i in range(8)]
    http = _StubHttp({
        "/1.0/json": {"info": {"requires_dist": []}},
        "/2.0/json": {"info": {"requires_dist":
                               [d + ">=0" for d in new_deps]}},
    })
    report = check_pypi_api_compat("foo", "1.0", "2.0", http=http)
    added = next(r for r in report.risks if r.kind == "deps_added")
    assert "(+3 more)" in added.detail


def test_no_http_skips_dep_signals():
    """Without a stubbed HttpClient, only the version-string-derived
    semver signal fires — useful for offline runs."""
    report = check_pypi_api_compat("foo", "1.0.0", "2.0.0")
    kinds = {r.kind for r in report.risks}
    assert kinds == {"semver_major"}


def test_http_failure_silent():
    """If PyPI returns garbage for one of the versions, we shouldn't
    crash; we just skip the dep-set comparison."""

    class _Broken:
        def get_json(self, url, headers=None):
            raise RuntimeError("boom")

    report = check_pypi_api_compat("foo", "1.0.0", "1.1.0", http=_Broken())
    # No major bump + dep fetch failed = empty risks.
    assert report.risks == []


def test_non_dict_pypi_response_handled():
    http = _StubHttp({
        "/1.0/json": "not a dict",
        "/1.1/json": {"info": {"requires_dist": []}},
    })
    report = check_pypi_api_compat("foo", "1.0", "1.1", http=http)
    # Non-dict response → no requires_dist → no dep risks.
    assert all(r.kind not in ("deps_added", "deps_removed")
               for r in report.risks)


def test_missing_requires_dist_treated_as_empty():
    http = _StubHttp({
        "/1.0/json": {"info": {}},
        "/1.1/json": {"info": {"requires_dist": ["six"]}},
    })
    report = check_pypi_api_compat("foo", "1.0", "1.1", http=http)
    # six is "added" relative to an empty old set.
    added = next(r for r in report.risks if r.kind == "deps_added")
    assert "six" in added.detail


# ---------------------------------------------------------------------------
# UpgradeCompatReport.overall_severity
# ---------------------------------------------------------------------------


def test_overall_severity_picks_max():
    rep = UpgradeCompatReport(
        ecosystem="PyPI",
        name="foo",
        from_version="1.0",
        to_version="2.0",
        risks=[
            UpgradeCompatRisk("semver_major", "...", "high"),
            UpgradeCompatRisk("deps_added", "...", "low"),
            UpgradeCompatRisk("deps_removed", "...", "info"),
        ],
    )
    assert rep.overall_severity == "high"


def test_overall_severity_empty_is_info():
    rep = UpgradeCompatReport(
        ecosystem="PyPI",
        name="foo",
        from_version="1.0",
        to_version="1.0.1",
        risks=[],
    )
    assert rep.overall_severity == "info"


# ---------------------------------------------------------------------------
# Cache integration — fetched payloads are reused
# ---------------------------------------------------------------------------


class _FakeCache:
    def __init__(self):
        self._store = {}

    def get(self, key, ttl_seconds=None):
        return self._store.get(key)

    def put(self, key, value, ttl_seconds=None):
        self._store[key] = value


def test_cache_used_for_requires_dist():
    cache = _FakeCache()
    http = _StubHttp({
        "/1.0/json": {"info": {"requires_dist": ["six"]}},
        "/1.1/json": {"info": {"requires_dist": ["six", "boto3"]}},
    })
    check_pypi_api_compat("foo", "1.0", "1.1", http=http, cache=cache)
    # Second call with the same versions should NOT hit HTTP again.
    http_call_count_after_first = len(http.calls)
    check_pypi_api_compat("foo", "1.0", "1.1", http=http, cache=cache)
    assert len(http.calls) == http_call_count_after_first


def test_requires_dist_uses_ttl_forever():
    """Per-version ``requires_dist`` is architecturally immutable
    on PyPI (re-publishing is forbidden), so the cache TTL must be
    TTL_FOREVER — operators get a refresh via
    ``raptor-sca clean-cache``, not by waiting out a 24h window.
    """
    from core.json.cache import TTL_FOREVER
    seen_ttls: list = []

    class _TtlCapturingCache:
        def __init__(self):
            self._store: dict = {}

        def get(self, key, *, ttl_seconds):
            seen_ttls.append(("get", ttl_seconds))
            return self._store.get(key)

        def put(self, key, value, *, ttl_seconds):
            seen_ttls.append(("put", ttl_seconds))
            self._store[key] = value

    cache = _TtlCapturingCache()
    http = _StubHttp({
        "/2.31.0/json": {"info": {"requires_dist": ["urllib3"]}},
    })
    from packages.sca.api_compat import _fetch_pypi_requires_dist
    _fetch_pypi_requires_dist(
        "requests", "2.31.0", http=http, cache=cache,
    )
    assert ("get", TTL_FOREVER) in seen_ttls, (
        f"get path must use TTL_FOREVER; saw: {seen_ttls}"
    )
    assert ("put", TTL_FOREVER) in seen_ttls, (
        f"put path must use TTL_FOREVER; saw: {seen_ttls}"
    )
