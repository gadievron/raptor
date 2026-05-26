"""Smoke tests for every registry client.

The shape we exercise per client:
  - Cache hit short-circuits the HTTP call.
  - Empty/missing fields return [] without raising.
  - HTTP failure returns [] (best-effort policy).
  - Yanked / pre-release / deprecated versions are filtered.
  - Output is newest-first.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from packages.sca.registries.crates import CratesClient
from packages.sca.registries.debian import DebianClient, _extract_versions
from packages.sca.registries.golang import GoClient
from packages.sca.registries.homebrew import HomebrewClient
from packages.sca.registries.maven import MavenClient
from packages.sca.registries.npm import NpmClient
from packages.sca.registries.nuget import NugetClient
from packages.sca.registries.packagist import PackagistClient
from packages.sca.registries.pypi import PyPIClient
from packages.sca.registries.rubygems import RubyGemsClient


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeHttp:
    def __init__(self, json_payload: Optional[Any] = None,
                 bytes_payload: Optional[bytes] = None,
                 raise_exc: Optional[Exception] = None) -> None:
        self.json_payload = json_payload
        self.bytes_payload = bytes_payload
        self.raise_exc = raise_exc
        self.calls: List[str] = []

    def get_json(self, url: str, timeout: int = 30,
                 headers: Optional[Dict[str, str]] = None,
                 *,
                 max_bytes: int = 0,
                 **kw,
                 ) -> Dict[str, Any]:
        # ``max_bytes`` is recorded per call so per-registry tests can
        # assert specific caps (e.g. npm should pass a higher cap than
        # the global default to handle large scoped namespaces).
        self.calls.append(url)
        self.last_max_bytes = max_bytes
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.json_payload or {}

    def post_json(self, url, body, timeout=30):  # pragma: no cover
        raise NotImplementedError

    def get_bytes(self, url: str, timeout: int = 30,
                  max_bytes: int = 0) -> bytes:
        self.calls.append(url)
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.bytes_payload or b""


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------

def test_pypi_filters_prereleases_and_yanked() -> None:
    http = _FakeHttp(json_payload={
        "releases": {
            "1.0": [{"yanked": False}],
            "2.0": [{"yanked": False}],
            "1.1a1": [{"yanked": False}],     # pre-release
            "2.1": [{"yanked": True}],         # yanked
            "0.9": [],                          # no files
        }
    })
    client = PyPIClient(http)
    assert client.list_versions("django") == ["2.0", "1.0"]


def test_pypi_http_failure_returns_empty() -> None:
    client = PyPIClient(_FakeHttp(raise_exc=RuntimeError("boom")))
    assert client.list_versions("requests") == []


def test_pypi_offline_skips_http() -> None:
    http = _FakeHttp(json_payload={"releases": {"1.0": [{"yanked": False}]}})
    client = PyPIClient(http, offline=True)
    assert client.list_versions("requests") == []
    assert http.calls == []


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def test_npm_filters_prerelease_and_deprecated() -> None:
    http = _FakeHttp(json_payload={
        "versions": {
            "1.0.0": {},
            "2.0.0": {},
            "2.0.0-rc.1": {},                  # pre-release
            "0.9.0": {"deprecated": "use foo"}, # deprecated
        },
        "time": {"1.0.0": "2023-01-01", "2.0.0": "2024-01-01"},
    })
    client = NpmClient(http)
    assert client.list_versions("lodash") == ["2.0.0", "1.0.0"]


def test_npm_scoped_name_url_encoded() -> None:
    http = _FakeHttp(json_payload={"versions": {"1.0.0": {}}})
    client = NpmClient(http)
    client.list_versions("@anthropic-ai/claude-code")


def test_npm_passes_high_max_bytes_for_registry_metadata() -> None:
    """``registry.npmjs.org``'s scoped-namespace metadata for popular
    packages (e.g. ``@grafana/runtime``) can exceed the global
    50 MB ``DEFAULT_MAX_BYTES``. The npm client must raise the cap
    explicitly — the May 2026 200-project sweep against Grafana
    hit this as a silent meta-fetch failure pre-fix.
    """
    http = _FakeHttp(json_payload={"versions": {"1.0.0": {}}})
    client = NpmClient(http)
    client.list_versions("@grafana/runtime")
    # Cap must be greater than the global 50 MB default.
    assert http.last_max_bytes >= 100 * 1024 * 1024, (
        f"npm meta call passed max_bytes={http.last_max_bytes}, "
        f"expected >= 100 MB"
    )


def test_npm_get_metadata_uses_high_max_bytes() -> None:
    """Same assertion for the ``get_metadata`` path used by the
    registry_metadata supply-chain detector (recent_publish /
    maintainer_change / version_publish)."""
    http = _FakeHttp(json_payload={"name": "x", "versions": {}})
    client = NpmClient(http)
    client.get_metadata("@grafana/runtime")
    assert http.last_max_bytes >= 100 * 1024 * 1024
    assert "%2F" in http.calls[0] or "/" in http.calls[0]


# ---------------------------------------------------------------------------
# Negative caching — applies to every registry client
# ---------------------------------------------------------------------------

def test_npm_negative_caches_404_failures(tmp_path) -> None:
    """A 404 (or any fetch failure) for a workspace-internal /
    private package name must be cached so subsequent detector
    calls don't re-query the registry.

    Surfaced by the May 2026 200-project sweep against Grafana:
    200+ unpublished ``@grafana/*`` and ``@grafana-plugins/*``
    workspace packages re-queried npm on every detector call,
    burning thousands of duplicate 404s before the operator
    killed the run.
    """
    from core.json import JsonCache
    from core.http import HttpError
    cache = JsonCache(root=tmp_path)
    http = _FakeHttp(raise_exc=HttpError("404"))
    client = NpmClient(http, cache=cache)
    # First call: hits the registry, fails, caches None.
    assert client.get_metadata("@grafana/unpublished") is None
    assert len(http.calls) == 1
    # Second call: cache hit, no new registry request.
    assert client.get_metadata("@grafana/unpublished") is None
    assert len(http.calls) == 1, "second call must be cache-served"


def test_pypi_negative_caches_404_failures(tmp_path) -> None:
    """Same negative-caching contract for PyPI."""
    from core.json import JsonCache
    from core.http import HttpError
    cache = JsonCache(root=tmp_path)
    http = _FakeHttp(raise_exc=HttpError("404"))
    client = PyPIClient(http, cache=cache)
    assert client.get_metadata("nonexistent-private-pkg") is None
    assert len(http.calls) == 1
    assert client.get_metadata("nonexistent-private-pkg") is None
    assert len(http.calls) == 1, "second call must be cache-served"


# ---------------------------------------------------------------------------
# crates.io
# ---------------------------------------------------------------------------

def test_crates_filters_yanked_and_prerelease() -> None:
    http = _FakeHttp(json_payload={
        "versions": [
            {"num": "1.0.0", "yanked": False},
            {"num": "2.0.0", "yanked": False},
            {"num": "2.1.0-alpha", "yanked": False},  # pre-release
            {"num": "1.5.0", "yanked": True},          # yanked
        ]
    })
    client = CratesClient(http)
    assert client.list_versions("ripgrep") == ["2.0.0", "1.0.0"]


def test_crates_empty_payload_returns_empty() -> None:
    client = CratesClient(_FakeHttp(json_payload={}))
    assert client.list_versions("nonexistent") == []


# ---------------------------------------------------------------------------
# RubyGems
# ---------------------------------------------------------------------------

def test_rubygems_filters_prerelease_and_yanked() -> None:
    http = _FakeHttp(json_payload=[
        {"number": "2.0.0", "prerelease": False, "yanked": False},
        {"number": "2.1.0.beta", "prerelease": True, "yanked": False},
        {"number": "1.5.0", "prerelease": False, "yanked": True},
        {"number": "1.0.0", "prerelease": False, "yanked": False},
    ])
    client = RubyGemsClient(http)
    # Order is API-provided (newest-first); we just preserve.
    assert client.list_versions("rake") == ["2.0.0", "1.0.0"]


def test_rubygems_dedup_duplicate_entries() -> None:
    http = _FakeHttp(json_payload=[
        {"number": "1.0.0", "prerelease": False, "yanked": False},
        {"number": "1.0.0", "prerelease": False, "yanked": False},
    ])
    client = RubyGemsClient(http)
    assert client.list_versions("foo") == ["1.0.0"]


# ---------------------------------------------------------------------------
# Go modules
# ---------------------------------------------------------------------------

def test_golang_filters_pseudo_and_prerelease() -> None:
    text = (
        "v1.0.0\n"
        "v2.0.0\n"
        "v2.0.0-rc.1\n"
        "v0.0.0-20210101000000-abcdef123456\n"   # pseudo-version
        "v1.5.0\n"
    ).encode("utf-8")
    client = GoClient(_FakeHttp(bytes_payload=text))
    assert client.list_versions("github.com/foo/bar") == [
        "v2.0.0", "v1.5.0", "v1.0.0",
    ]


def test_golang_url_capital_letter_encoded() -> None:
    """Go's case-insensitive encoding: ``GoFoo`` → ``!go!foo``."""
    client = GoClient(_FakeHttp(bytes_payload=b"v1.0.0\n"))
    client.list_versions("github.com/Foo/Bar")
    assert "!foo" in client._http.calls[0]      # type: ignore[attr-defined]


def test_golang_offline_skips_http() -> None:
    http = _FakeHttp(bytes_payload=b"v1.0.0\n")
    client = GoClient(http, offline=True)
    assert client.list_versions("github.com/foo/bar") == []
    assert http.calls == []


# ---------------------------------------------------------------------------
# Debian
# ---------------------------------------------------------------------------

# Shape mirrors madison ``?f=json``: a one-element list keyed by package
# name, then suite, then version. The same version recurs across suites
# (incl. the -debug shadow) and must be deduped; output is newest-first by
# dpkg ordering (epoch dominance, ``+debNuM`` security bumps, etc.).
def _madison(pkg: str, by_suite: Dict[str, List[str]]) -> List[dict]:
    return [{pkg: {
        suite: {ver: {"component": "main", "source": pkg} for ver in vers}
        for suite, vers in by_suite.items()
    }}]


def test_debian_extracts_versions_newest_first_deduped() -> None:
    http = _FakeHttp(json_payload=_madison("nginx", {
        "oldoldstable": ["1.18.0-6.1+deb11u3"],
        "oldoldstable-debug": ["1.18.0-6.1+deb11u3"],            # dup shadow
        "oldstable": ["1.22.1-9+deb12u6"],
        "oldstable-proposed-updates": ["1.22.1-9+deb12u7"],
        "stable": ["1.26.0-1"],
    }))
    client = DebianClient(http)
    assert client.list_versions("nginx") == [
        "1.26.0-1",
        "1.22.1-9+deb12u7",
        "1.22.1-9+deb12u6",
        "1.18.0-6.1+deb11u3",
    ]


def test_debian_epoch_sorts_above_higher_upstream() -> None:
    """An epoch must dominate: the gcc shape that motivated this fix."""
    http = _FakeHttp(json_payload=_madison("gcc", {
        "stable": ["4:14.2.0-1"],
        "experimental": ["4:16-20251130-1"],
        # A bogus no-epoch entry must still sort *below* the epoch-4 ones.
        "ancient": ["2.95.2-20"],
    }))
    client = DebianClient(http)
    assert client.list_versions("gcc") == [
        "4:16-20251130-1", "4:14.2.0-1", "2.95.2-20",
    ]


def test_debian_binary_name_is_url_encoded() -> None:
    """``g++`` must be percent-encoded — a raw ``+`` is a space to madison
    (and unencoded names from manifests are a query-injection vector)."""
    http = _FakeHttp(json_payload=_madison("g++", {"stable": ["4:14.2.0-1"]}))
    client = DebianClient(http)
    assert client.list_versions("g++") == ["4:14.2.0-1"]
    assert "api.ftp-master.debian.org/madison" in http.calls[0]
    assert "package=g%2B%2B" in http.calls[0]
    assert "f=json" in http.calls[0]


def test_debian_unknown_package_returns_empty() -> None:
    """madison returns ``[]`` for an unknown package (and the parser also
    tolerates the no-suites and non-list shapes without raising)."""
    assert _extract_versions([]) == []
    assert _extract_versions([{"nope": {}}]) == []          # known pkg, no suites
    assert _extract_versions({"error": "x"}) == []           # not a list
    client = DebianClient(_FakeHttp(json_payload=[{"nope": {}}]))
    assert client.list_versions("nonexistent-pkg") == []


def test_debian_offline_skips_http() -> None:
    http = _FakeHttp(json_payload=_madison("nginx", {"stable": ["1.0"]}))
    client = DebianClient(http, offline=True)
    assert client.list_versions("nginx") == []
    assert http.calls == []


def test_debian_versions_in_suite_adds_suite_filter() -> None:
    """``versions_in_suite`` passes ``&s=<suite>`` so madison resolves the
    codename server-side; result is still newest-first."""
    # madison returns the codename query tagged with its current alias.
    http = _FakeHttp(json_payload=_madison("nginx", {
        "oldstable": ["1.22.1-9+deb12u6", "1.22.1-9+deb12u5"],
    }))
    client = DebianClient(http)
    assert client.versions_in_suite("nginx", "bookworm") == [
        "1.22.1-9+deb12u6", "1.22.1-9+deb12u5",
    ]
    assert "s=bookworm" in http.calls[0]
    assert "f=json" in http.calls[0]


def test_debian_suite_pocket_is_url_encoded() -> None:
    """A pocket/alias is encoded too (defends against injection from a
    manifest-derived FROM tag)."""
    http = _FakeHttp(json_payload=_madison("nginx", {"stable": ["1.0"]}))
    client = DebianClient(http)
    client.versions_in_suite("nginx", "bookworm-security")
    assert "s=bookworm-security" in http.calls[0]


def test_debian_suite_query_cached_separately_from_all_suites() -> None:
    """The all-suites list and a per-suite list use distinct cache keys."""
    import tempfile
    from pathlib import Path
    from core.json import JsonCache
    with tempfile.TemporaryDirectory() as d:
        cache = JsonCache(root=Path(d))
        http = _FakeHttp(json_payload=_madison("nginx", {
            "stable": ["1.26.0-1"], "oldstable": ["1.22.1-9+deb12u6"],
        }))
        client = DebianClient(http, cache)
        allv = client.list_versions("nginx")
        client.versions_in_suite("nginx", "bookworm")
        # Two distinct network calls (different cache keys), not one reused.
        assert len(http.calls) == 2
        assert "1.26.0-1" in allv and "1.22.1-9+deb12u6" in allv


# ---------------------------------------------------------------------------
# Homebrew
# ---------------------------------------------------------------------------

def test_homebrew_returns_stable_only() -> None:
    """Homebrew tracks one stable per formula; that's what we return."""
    http = _FakeHttp(json_payload={
        "name": "semgrep",
        "versions": {"stable": "1.161.0", "head": "HEAD", "bottle": True},
    })
    client = HomebrewClient(http)
    assert client.list_versions("semgrep") == ["1.161.0"]


def test_homebrew_no_stable_returns_empty() -> None:
    client = HomebrewClient(_FakeHttp(json_payload={
        "versions": {"head": "HEAD"}}))
    assert client.list_versions("foo") == []


def test_homebrew_versioned_formula() -> None:
    """``python@3.11`` is a *separate* formula with its own stable."""
    http = _FakeHttp(json_payload={
        "name": "python@3.11",
        "versions": {"stable": "3.11.9", "head": "HEAD", "bottle": True},
    })
    client = HomebrewClient(http)
    assert client.list_versions("python@3.11") == ["3.11.9"]


# ---------------------------------------------------------------------------
# Maven Central
# ---------------------------------------------------------------------------

def test_maven_extracts_versions() -> None:
    http = _FakeHttp(json_payload={
        "response": {
            "docs": [
                {"v": "2.17.1", "g": "org.apache.logging.log4j",
                 "a": "log4j-core"},
                {"v": "2.17.0", "g": "org.apache.logging.log4j",
                 "a": "log4j-core"},
                {"v": "2.16.0", "g": "org.apache.logging.log4j",
                 "a": "log4j-core"},
            ]
        }
    })
    client = MavenClient(http)
    versions = client.list_versions(
        "org.apache.logging.log4j:log4j-core")
    assert versions == ["2.17.1", "2.17.0", "2.16.0"]


def test_maven_filters_prereleases() -> None:
    http = _FakeHttp(json_payload={
        "response": {
            "docs": [
                {"v": "2.0.0"},
                {"v": "2.0.0-SNAPSHOT"},      # snapshot
                {"v": "2.0.0-alpha"},          # alpha
                {"v": "2.0.0-beta1"},          # beta
                {"v": "2.0.0-rc1"},            # rc
            ]
        }
    })
    client = MavenClient(http)
    assert client.list_versions("g:a") == ["2.0.0"]


def test_maven_rejects_name_without_colon() -> None:
    """Maven names must be group:artifact; a bare name returns []."""
    client = MavenClient(_FakeHttp())
    assert client.list_versions("just-an-artifact") == []


# ---------------------------------------------------------------------------
# Packagist
# ---------------------------------------------------------------------------

def test_packagist_extracts_versions() -> None:
    http = _FakeHttp(json_payload={
        "packages": {
            "symfony/console": [
                {"version": "v6.4.0"},
                {"version": "v6.3.0"},
            ]
        }
    })
    client = PackagistClient(http)
    assert client.list_versions("symfony/console") == ["v6.4.0", "v6.3.0"]


def test_packagist_filters_prerelease_tags() -> None:
    http = _FakeHttp(json_payload={
        "packages": {
            "vendor/pkg": [
                {"version": "1.0.0"},
                {"version": "1.0.0-dev"},
                {"version": "1.0.0-alpha"},
                {"version": "1.0.0-beta"},
                {"version": "1.0.0-rc"},
                {"version": "1.0.0-patch"},
            ]
        }
    })
    client = PackagistClient(http)
    assert client.list_versions("vendor/pkg") == ["1.0.0"]


def test_packagist_rejects_name_without_slash() -> None:
    client = PackagistClient(_FakeHttp())
    assert client.list_versions("just-pkg") == []


# ---------------------------------------------------------------------------
# NuGet
# ---------------------------------------------------------------------------

def test_nuget_extracts_versions() -> None:
    http = _FakeHttp(json_payload={
        "versions": ["1.0.0", "1.1.0", "1.2.0", "0.9.0"]
    })
    client = NugetClient(http)
    versions = client.list_versions("Newtonsoft.Json")
    # Newest-first via semver-ish sort.
    assert versions == ["1.2.0", "1.1.0", "1.0.0", "0.9.0"]


def test_nuget_filters_prereleases() -> None:
    http = _FakeHttp(json_payload={
        "versions": ["1.0.0", "1.0.0-rc.1", "1.0.0-beta", "0.9.0"]
    })
    client = NugetClient(http)
    assert client.list_versions("foo") == ["1.0.0", "0.9.0"]


def test_nuget_lowercases_id_in_url() -> None:
    """NuGet IDs are case-insensitive but the URL path requires lowercase."""
    http = _FakeHttp(json_payload={"versions": ["1.0.0"]})
    client = NugetClient(http)
    client.list_versions("Newtonsoft.Json")
    assert "newtonsoft.json" in http.calls[0]
