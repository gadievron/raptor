"""Tests for the shared URL-path chokepoint (``registries._url``).

Registry clients interpolate package names / versions that originate
in the SCANNED repository's manifests into request URLs — hostile
input. These tests pin, per client:

  1. Traversal / metachar names are rejected (or safely encoded into
     one path segment) BEFORE any HTTP request — asserted against the
     URL the stub HTTP client actually receives.
  2. Normal names produce the same URLs as before the chokepoint.
  3. Maven POM fetches honour the configured private base URL.
  4. Cache keys mix in the resolved base URL for every client with a
     configurable registry, so a private-mirror answer is never
     served as the public registry's (or vice versa).
"""

from __future__ import annotations

from typing import Any

import pytest

from packages.sca.registries._url import (
    UnsafeUrlComponentError,
    quote_path,
    quote_segment,
    registry_cache_key,
)


class _RecordingHttp:
    """Stub HTTP client recording every requested URL."""

    def __init__(self, json_payload: Any = None) -> None:
        self.json_payload = json_payload
        self.calls: list[str] = []
        self.request_calls: list[str] = []
        self.request_headers: list[dict | None] = []

    def get_json(self, url: str, **kw: Any) -> Any:
        self.calls.append(url)
        return self.json_payload if self.json_payload is not None else {}

    def request(self, method: str, url: str, **kw: Any):
        self.request_calls.append(url)
        self.request_headers.append(kw.get("headers"))

        class _Resp:
            status_code = 200
            content = (b"<project xmlns='http://maven.apache.org/POM/4.0.0'>"
                       b"</project>")
        return _Resp()

    def get_bytes(self, url: str, **kw: Any) -> bytes:
        self.calls.append(url)
        return b""


# ---------------------------------------------------------------------------
# Chokepoint primitives
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "", ".", "..", "a/b", "a b", "a\tb", "a\nb", "a\x00b", "a\x7fb",
])
def test_quote_segment_rejects_unsafe(bad: str) -> None:
    with pytest.raises(UnsafeUrlComponentError):
        quote_segment(bad)


def test_quote_segment_encodes_metachars_and_keeps_normal() -> None:
    assert quote_segment("requests") == "requests"
    assert quote_segment("newtonsoft.json") == "newtonsoft.json"
    assert quote_segment("a?b#c&d") == "a%3Fb%23c%26d"
    assert quote_segment("@babel", safe="@") == "@babel"


def test_quote_segment_never_allows_slash_or_percent_safe() -> None:
    with pytest.raises(ValueError):
        quote_segment("x", safe="/")
    with pytest.raises(ValueError):
        quote_segment("x", safe="%")


def test_quote_path_validates_each_segment() -> None:
    assert quote_path("vendor/pkg") == "vendor/pkg"
    for bad in ("vendor/../pkg", "vendor//pkg", "a/./b", "/lead", "trail/"):
        with pytest.raises(UnsafeUrlComponentError):
            quote_path(bad)
    with pytest.raises(UnsafeUrlComponentError):
        quote_path("a/b/c", expected_segments=2)


def test_registry_cache_key_base_url_digest_distinct() -> None:
    public = registry_cache_key("p", "name",
                                base_url="https://pypi.org")
    mirror = registry_cache_key("p", "name",
                                base_url="https://mirror.internal")
    assert public != mirror
    # No base → legacy-compatible key shape.
    assert registry_cache_key("p", "a/b") == "p:a%2Fb"


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------

def test_pypi_normal_name_url_unchanged() -> None:
    from packages.sca.registries.pypi import PyPIClient
    http = _RecordingHttp({"releases": {}})
    PyPIClient(http).get_metadata("requests")
    assert http.calls == ["https://pypi.org/pypi/requests/json"]


def test_pypi_traversal_name_never_fetched() -> None:
    from packages.sca.registries.pypi import PyPIClient
    http = _RecordingHttp()
    client = PyPIClient(http)
    # PEP 503 canonicalisation collapses ``..`` runs but keeps ``/``;
    # the chokepoint rejects the spliced shape outright.
    assert client.get_metadata("requests/json/../../simple") is None
    assert client.list_versions("../requests") == []
    assert http.calls == []


def test_pypi_version_metachars_never_fetched() -> None:
    from packages.sca.registries.pypi import PyPIClient
    http = _RecordingHttp()
    client = PyPIClient(http)
    assert client.get_version_metadata("requests", "1.0/../2.0") is None
    assert http.calls == []
    # Normal version: URL unchanged.
    http2 = _RecordingHttp({"info": {}})
    PyPIClient(http2).get_version_metadata("requests", "2.31.0")
    assert http2.calls == ["https://pypi.org/pypi/requests/2.31.0/json"]


def test_pypi_cache_key_distinct_per_base_url(monkeypatch, tmp_path) -> None:
    """The same package via the public registry and via a private
    mirror must occupy DISTINCT cache entries — serving a mirror's
    answer as the public one (or vice versa) inverts dependency-
    confusion verdicts."""
    from core.json import JsonCache
    from packages.sca.registries.pypi import PyPIClient
    cache = JsonCache(root=tmp_path)

    monkeypatch.delenv("PIP_INDEX_URL", raising=False)
    http_pub = _RecordingHttp({"releases": {"9.9": [{"yanked": False}]}})
    PyPIClient(http_pub, cache).get_metadata("requests")
    assert len(http_pub.calls) == 1

    monkeypatch.setenv("PIP_INDEX_URL", "https://mirror.internal/simple")
    http_mirror = _RecordingHttp({"releases": {"1.0": [{"yanked": False}]}})
    client_mirror = PyPIClient(http_mirror, cache)
    meta = client_mirror.get_metadata("requests")
    assert len(http_mirror.calls) == 1, (
        "mirror lookup must not be served from the public entry"
    )
    assert meta["releases"] == {"1.0": [{"yanked": False}]}
    assert "mirror.internal" in http_mirror.calls[0]


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def test_npm_cache_key_distinct_per_base_url(monkeypatch, tmp_path) -> None:
    from core.json import JsonCache
    from packages.sca.registries.npm import NpmClient
    cache = JsonCache(root=tmp_path)

    monkeypatch.delenv("NPM_CONFIG_REGISTRY", raising=False)
    http_pub = _RecordingHttp({"name": "left-pad", "versions": {}})
    NpmClient(http_pub, cache).get_metadata("left-pad")
    assert len(http_pub.calls) == 1

    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://npm.mirror.internal")
    http_mirror = _RecordingHttp({"name": "left-pad", "versions": {}})
    NpmClient(http_mirror, cache).get_metadata("left-pad")
    assert len(http_mirror.calls) == 1, (
        "mirror lookup must not be served from the public entry"
    )


# ---------------------------------------------------------------------------
# crates.io / RubyGems / NuGet / Packagist / Homebrew / Go
# ---------------------------------------------------------------------------

def test_crates_traversal_rejected_normal_unchanged() -> None:
    from packages.sca.registries.crates import CratesClient
    http = _RecordingHttp()
    client = CratesClient(http)
    assert client.get_metadata("../admin") is None
    assert client.get_version_dependencies("serde", "1.0/../2.0") is None
    assert http.calls == []
    http2 = _RecordingHttp({"versions": []})
    CratesClient(http2).get_metadata("serde")
    assert http2.calls == ["https://crates.io/api/v1/crates/serde"]


def test_rubygems_traversal_rejected_normal_unchanged() -> None:
    from packages.sca.registries.rubygems import RubyGemsClient
    http = _RecordingHttp()
    client = RubyGemsClient(http)
    assert client.list_versions("rack/../../admin") == []
    assert client.get_metadata("rack\n.json") is None
    assert client.get_version_metadata("rack", "..") is None
    assert http.calls == []
    http2 = _RecordingHttp([])
    RubyGemsClient(http2).list_versions("rack")
    assert http2.calls == ["https://rubygems.org/api/v1/versions/rack.json"]


def test_rubygems_metachar_name_encoded_into_one_segment() -> None:
    """A name carrying URL metachars is confined to one encoded path
    segment — it 404s upstream rather than swapping the endpoint."""
    from packages.sca.registries.rubygems import RubyGemsClient
    http = _RecordingHttp([])
    RubyGemsClient(http).list_versions("rack?x=1")
    assert http.calls == [
        "https://rubygems.org/api/v1/versions/rack%3Fx%3D1.json",
    ]


def test_nuget_traversal_rejected_normal_unchanged() -> None:
    from packages.sca.registries.nuget import NugetClient
    http = _RecordingHttp()
    client = NugetClient(http)
    assert client.list_versions("../index") == []
    assert client.get_nuspec("Pkg/../Other", "1.0") is None
    assert http.calls == []
    http2 = _RecordingHttp({"versions": ["1.0.0"]})
    NugetClient(http2).list_versions("Newtonsoft.Json")
    assert http2.calls == [
        "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json",
    ]


def test_packagist_normal_unchanged() -> None:
    from packages.sca.registries.packagist import PackagistClient
    http = _RecordingHttp({"packages": {}})
    PackagistClient(http).get_metadata("symfony/console")
    assert http.calls == [
        "https://repo.packagist.org/p2/symfony/console.json",
    ]


def test_packagist_traversal_and_extra_segments_rejected() -> None:
    from packages.sca.registries.packagist import PackagistClient
    http = _RecordingHttp()
    client = PackagistClient(http)
    assert client.get_metadata("vendor/../pkg") is None
    assert client.get_metadata("vendor/pkg/extra") is None
    assert http.calls == []


def test_homebrew_traversal_confined_normal_unchanged() -> None:
    from packages.sca.registries.homebrew import HomebrewClient
    http = _RecordingHttp()
    client = HomebrewClient(http)
    assert client.list_versions("..") == []
    assert http.calls == []
    http2 = _RecordingHttp({"versions": {"stable": "3.11.9"}})
    HomebrewClient(http2).list_versions("python@3.11")
    assert http2.calls == [
        "https://formulae.brew.sh/api/formula/python@3.11.json",
    ]
    # Tap-qualified names (``user/tap/formula``) aren't served by
    # formulae.brew.sh — not-found path, no request made.
    http3 = _RecordingHttp({})
    assert HomebrewClient(http3).list_versions("user/tap/formula") == []
    assert http3.calls == []


def test_golang_traversal_rejected_normal_unchanged() -> None:
    from packages.sca.registries.golang import GoClient
    http = _RecordingHttp()
    client = GoClient(http)
    assert client.list_versions("github.com/../@latest") == []
    assert client.list_versions("a//b") == []
    assert http.calls == []
    http2 = _RecordingHttp()
    GoClient(http2).list_versions("github.com/BurntSushi/toml")
    assert http2.calls == [
        "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/list",
    ]


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

def test_maven_solr_query_encodes_metachars(monkeypatch) -> None:
    from packages.sca.registries.maven import MavenClient
    monkeypatch.delenv("RAPTOR_SCA_MAVEN_REGISTRY", raising=False)
    http = _RecordingHttp({"response": {"docs": []}})
    MavenClient(http).list_versions("com.example:artifact&rows=9999")
    assert http.calls == [
        "https://search.maven.org/solrsearch/select"
        "?q=g:com.example+AND+a:artifact%26rows%3D9999"
        "&core=gav&rows=200&wt=json",
    ]


def test_maven_pom_traversal_rejected(monkeypatch) -> None:
    from packages.sca.registries.maven import MavenClient
    monkeypatch.delenv("RAPTOR_SCA_MAVEN_REGISTRY", raising=False)
    http = _RecordingHttp()
    client = MavenClient(http)
    assert client.get_pom("com..example:artifact", "1.0") is None
    assert client.get_pom("com.example:artifact", "1.0/../2.0") is None
    assert client.get_pom("com/example:artifact", "1.0") is None
    assert http.request_calls == []


def test_maven_pom_default_public_url_unchanged(monkeypatch) -> None:
    from packages.sca.registries.maven import MavenClient
    monkeypatch.delenv("RAPTOR_SCA_MAVEN_REGISTRY", raising=False)
    http = _RecordingHttp()
    MavenClient(http).get_pom("com.example:artifact", "1.2.3")
    assert http.request_calls == [
        "https://repo1.maven.org/maven2/com/example/"
        "artifact/1.2.3/artifact-1.2.3.pom",
    ]


def test_maven_pom_honours_private_base_url_and_auth(monkeypatch) -> None:
    """A configured private Maven registry must serve POM fetches too
    (with the configured Authorization header) — not just the search
    endpoint. Pre-fix ``get_pom`` hardwired repo1.maven.org."""
    from packages.sca.registries.maven import MavenClient
    monkeypatch.setenv(
        "RAPTOR_SCA_MAVEN_REGISTRY", "https://maven.mirror.internal",
    )
    monkeypatch.setenv("RAPTOR_SCA_MAVEN_AUTH", "Bearer sekrit")
    http = _RecordingHttp()
    MavenClient(http).get_pom("com.example:artifact", "1.2.3")
    assert http.request_calls == [
        "https://maven.mirror.internal/maven2/com/example/"
        "artifact/1.2.3/artifact-1.2.3.pom",
    ]
    assert http.request_headers == [{"Authorization": "Bearer sekrit"}]


def test_maven_cache_key_distinct_per_base_url(
    monkeypatch, tmp_path,
) -> None:
    from core.json import JsonCache
    from packages.sca.registries.maven import MavenClient
    cache = JsonCache(root=tmp_path)
    payload = {"response": {"docs": [{"v": "1.0.0"}]}}

    monkeypatch.delenv("RAPTOR_SCA_MAVEN_REGISTRY", raising=False)
    http_pub = _RecordingHttp(payload)
    MavenClient(http_pub, cache).list_versions("g:a")
    assert len(http_pub.calls) == 1

    monkeypatch.setenv(
        "RAPTOR_SCA_MAVEN_REGISTRY", "https://maven.mirror.internal",
    )
    http_mirror = _RecordingHttp(payload)
    MavenClient(http_mirror, cache).list_versions("g:a")
    assert len(http_mirror.calls) == 1, (
        "mirror lookup must not be served from the public entry"
    )
